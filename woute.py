#!/usr/bin/env python3
"""woute - Route traffic through WireGuard tunnels on macOS"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
import tty
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

VERSION   = "1.0.0"
CONF_PATH = Path.home() / ".config/woute/woute.conf"
STATE_FILE = Path.home() / ".config/woute/state.json"
LOG_DIR   = Path.home() / ".config/woute/logs"

_FMT  = "%(asctime)s  %(levelname)-7s  %(message)s"
_DFMT = "%Y-%m-%d %H:%M:%S %z"
logging.basicConfig(level=logging.INFO, format=_FMT, datefmt=_DFMT)
log = logging.getLogger("woute")


# ── Dataclasses ───────────────────────────────────────────

@dataclass
class WireGuardConfig:
    name:           str
    private_key:    str  = ""
    address:        str  = ""
    dns_servers:    list = field(default_factory=list)
    public_key:     str  = ""
    endpoint:       str  = ""
    allowed_ips:    str  = "0.0.0.0/0"
    interface_name: str  = ""


@dataclass
class Rule:
    value:    str
    action:   str                       # "direct" | "block" | "route"
    target:   Optional[str]   = None   # tunnel/group name when action == "route"
    compiled: Optional[object] = None  # re.Pattern for hostname rules
    network:  Optional[object] = None  # ipaddress.IPv4Network for IP rules

    def __str__(self):
        dest = self.target if self.action == "route" else self.action
        return f"{self.value} -> {dest}"

    @classmethod
    def from_line(cls, line):
        if " -> " not in line:
            return None
        pattern, _, target = line.partition(" -> ")
        pattern, target    = pattern.strip(), target.strip()
        tl     = target.lower()
        action = "direct" if tl == "direct" else "block" if tl == "block" else "route"
        rtarget = target if action == "route" else None
        if "/" in pattern and "*" not in pattern:
            try:
                return cls(value=pattern, action=action, target=rtarget,
                           network=ipaddress.ip_network(pattern, strict=False))
            except ValueError:
                pass
        return cls(value=pattern, action=action, target=rtarget,
                   compiled=_compile_pattern(pattern))


@dataclass
class Config:
    listen_host:        str  = "127.0.0.1"
    listen_port:        int  = 7890
    log_level:          str  = "INFO"
    log_retention_days: int  = 7
    dns_servers:        list = field(default_factory=lambda: ["1.1.1.1", "1.0.0.1"])
    rules:         list = field(default_factory=list)
    tunnels:       dict = field(default_factory=dict)
    tunnel_groups: dict = field(default_factory=dict)


# ── Pattern compiler ──────────────────────────────────────

def _compile_pattern(pattern: str) -> Optional[object]:
    if pattern in ("*", "default"):
        return None
    if pattern.startswith("*."):
        return re.compile(rf'^(?:.*\.)?{re.escape(pattern[2:])}$', re.IGNORECASE)
    regex = "^" + ".*".join(re.escape(p) for p in pattern.split("*")) + "$"
    return re.compile(regex, re.IGNORECASE)


# ── Config parser ─────────────────────────────────────────

_WG_KEYS = {"private-key": "private_key", "address": "address",
            "public-key":  "public_key",  "endpoint": "endpoint",
            "allowed-ips": "allowed_ips"}


def parse_config(path) -> Config:
    config, section, tname = Config(), None, None
    for lineno, raw in enumerate(Path(path).read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line[0] in "#/": continue
        if line.startswith("[") and line.endswith("]"):
            hdr = line[1:-1].strip(); up = hdr.upper()
            if up.startswith("TUNNEL:"):
                tname = hdr.split(":", 1)[1].strip()
                if not tname: log.warning(f"line {lineno}: [Tunnel:] missing name"); section = None; continue
                section = "TUNNEL"
                config.tunnels.setdefault(tname, WireGuardConfig(name=tname))
            elif up in ("TUNNEL GROUP", "GROUP"): section, tname = "GROUP", None
            else: section, tname = up, None
            continue
        if section == "RULE":
            r = Rule.from_line(line)
            if r is None: log.warning(f"line {lineno}: malformed rule: {line!r}")
            else: config.rules.append(r)
            continue
        if "=" not in line: continue
        raw_key, _, val = line.partition("=")
        key, val = raw_key.strip().lower(), val.split("#", 1)[0].strip().strip('"')
        if section == "GENERAL":
            if key == "socks5-listen":
                parts = val.rsplit(":", 1)
                config.listen_port = int(parts[-1])
                if len(parts) == 2: config.listen_host = parts[0]
            elif key in ("log-level", "loglevel"): config.log_level = val.upper()
            elif key in ("log-retention", "log-retention-days"):
                try: config.log_retention_days = max(0, int(val))
                except ValueError: log.warning(f"line {lineno}: invalid log-retention: {val!r}")
            elif key == "dns": config.dns_servers = [s.strip() for s in val.split(",")]
        elif section == "GROUP":
            if (members := [p.strip() for p in val.split(",") if p.strip()]):
                config.tunnel_groups[raw_key.strip()] = members
        elif section == "TUNNEL" and tname:
            wg = config.tunnels[tname]
            if key == "dns": wg.dns_servers = [s.strip() for s in val.split(",")]
            elif key in _WG_KEYS: setattr(wg, _WG_KEYS[key], val)

    seen, known = {}, set(config.tunnels) | set(config.tunnel_groups)
    for name, wg in config.tunnels.items():
        if not wg.private_key: log.warning(f"Tunnel [{name}] missing private-key")
        if not wg.address: log.warning(f"Tunnel [{name}] missing address")
        elif wg.address in seen: log.warning(f"Tunnel [{name}] same address as [{seen[wg.address]}]")
        else: seen[wg.address] = name
    for r in config.rules:
        if r.action == "route" and r.target not in known:
            log.warning(f"Rule '{r.value}' routes to unknown tunnel/group '{r.target}'")
    for gname, members in config.tunnel_groups.items():
        for m in members:
            if m not in config.tunnels: log.warning(f"Group '{gname}' references unknown tunnel '{m}'")
    return config


# ── State ─────────────────────────────────────────────────

_counters:    dict = {"routed": 0, "direct": 0, "blocked": 0, "total": 0}
_recent:      list = []   # (ts, label, host, target_name)
_tun_status:  dict = {}   # name → [iface, up, addr, endpoint]
_hb:          dict = {}   # name → [ts, ok]
_state_lock        = threading.Lock()


def _record(action: str, host: str, wg: Optional[WireGuardConfig]):
    label = "WIREGUARD" if action == "route" else action.upper()
    ts    = time.strftime("%H:%M:%S")
    key   = "routed" if action == "route" else "blocked" if action == "block" else action
    with _state_lock:
        _counters[key]     += 1
        _counters["total"] += 1
        _recent.insert(0, (ts, label, host, wg.name if wg else ""))
        if len(_recent) > 200: _recent.pop()


def _dump_state(config: Config, conf_path, started_ts: float):
    with _state_lock:
        data = {
            "version": VERSION, "pid": os.getpid(),
            "conf_path": str(Path(conf_path).resolve()),
            "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started_ts)),
            "started_ts": started_ts, "updated": time.strftime("%H:%M:%S"),
            "counters": dict(_counters), "recent": [list(r) for r in _recent],
            "tunnel_status": dict(_tun_status), "hb": dict(_hb),
            "rules": [{"value": r.value, "action": r.action, "target": r.target or ""} for r in config.rules],
            "tunnels": list(config.tunnels.keys()),
            "tunnel_groups": {k: list(v) for k, v in config.tunnel_groups.items()},
        }
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    try: STATE_FILE.write_text(json.dumps(data))
    except OSError: pass


async def _state_dumper(config: Config, conf_path, started_ts: float):
    try:
        while True:
            _dump_state(config, conf_path, started_ts)
            await asyncio.sleep(1)
    except (asyncio.CancelledError, KeyboardInterrupt): pass


# ── SOCKS5 proxy lifecycle ────────────────────────────────

def _active_services() -> list:
    r = subprocess.run(["networksetup", "-listallnetworkservices"],
                       capture_output=True, text=True, check=False)
    return [l.strip() for l in r.stdout.splitlines()
            if l.strip() and not l.startswith("*") and "asterisk" not in l.lower()]


def _sys_proxy(host: Optional[str] = None, port: int = 0):
    for svc in _active_services():
        if host:
            subprocess.run(["networksetup", "-setsocksfirewallproxy", svc, host, str(port)], check=False)
        subprocess.run(["networksetup", "-setsocksfirewallproxystate", svc, "on" if host else "off"], check=False)
    log.warning(f"SOCKS5 proxy set → {host}:{port}" if host else "SOCKS5 proxy cleared")


# ── Rule matching ─────────────────────────────────────────

def _resolve_target(name: str, tunnels: dict, groups: dict) -> Optional[WireGuardConfig]:
    members = groups.get(name)
    if members:
        for m in members:
            wg = tunnels.get(m)
            if not wg: continue
            age = _handshake_age(wg.interface_name)
            if age is None or age > 180:
                log.debug(f"Tunnel '{m}' stale (age={age}s), skipping")
                continue
            return wg
        return next((tunnels[m] for m in members if m in tunnels), None)
    return tunnels.get(name)


async def match_rule(host: str, port: int, config: Config) -> tuple:
    ip = None
    for rule in config.rules:
        if rule.network:
            if ip is None:
                try:   ip = await asyncio.get_event_loop().run_in_executor(
                               None, socket.gethostbyname, host)
                except (socket.gaierror, OSError): ip = ""
            try:    matched = bool(ip and ipaddress.ip_address(ip) in rule.network)
            except (ValueError, TypeError): matched = False
        else:
            matched = rule.compiled is None or bool(rule.compiled.match(host))
        if matched:
            if rule.action == "route" and rule.target:
                wg = _resolve_target(rule.target, config.tunnels, config.tunnel_groups)
                if not wg:
                    log.warning(f"Rule target '{rule.target}' unresolvable, using direct")
                    return "direct", None
                return rule.action, wg
            return rule.action, None
    return "direct", None


# ── WireGuard manager ─────────────────────────────────────

class WireGuardManager:

    def __init__(self, config: Config):
        self.config = config
        self._host_routes: list = []
        self._peer_routes: set  = set()
        self._lock = threading.Lock()

    def _run(self, cmd: list, check: bool = True) -> subprocess.CompletedProcess:
        log.debug(f"exec: {' '.join(cmd)}")
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def start_all(self):
        if not self.config.tunnels: return
        for tool in ("wg-quick", "wg"):
            if not shutil.which(tool):
                raise RuntimeError(f"'{tool}' not found — brew install wireguard-go wireguard-tools")
        if os.geteuid() != 0:
            raise RuntimeError("WireGuard tunnels require root. Run with: sudo woute start")
        run_dir = Path.home() / ".config/woute/run"
        for name in self.config.tunnels:
            nf, conf = Path(f"/var/run/wireguard/{name}.name"), run_dir / f"{name}.conf"
            if nf.exists() and conf.exists():
                log.warning(f"Cleaning up stale tunnel '{name}'")
                subprocess.run(["wg-quick", "down", str(conf)],
                               capture_output=True, text=True, check=False)
        log.warning(f"Starting {len(self.config.tunnels)} WireGuard tunnel(s)...")
        for name, wg in self.config.tunnels.items():
            if wg.endpoint:
                try: self._peer_routes.add(
                    (socket.gethostbyname(wg.endpoint.rsplit(":", 1)[0]), wg.address))
                except socket.gaierror: pass
            try: self._start_one(name, wg)
            except subprocess.CalledProcessError as e:
                err = (e.stderr or "").strip().replace("\n", "; ") or str(e)
                log.error(f"Failed to start tunnel '{name}': {err}")
            except Exception as e: log.error(f"Failed to start tunnel '{name}': {e}")

    def _start_one(self, name: str, wg: WireGuardConfig):
        run_dir = Path.home() / ".config/woute/run"
        run_dir.mkdir(parents=True, exist_ok=True)
        conf_path = run_dir / f"{name}.conf"
        body = [f"[Interface]\nPrivateKey = {wg.private_key}\nAddress = {wg.address}\nTable = off\n",
                f"[Peer]\nPublicKey = {wg.public_key}\nAllowedIPs = {wg.allowed_ips}\nPersistentKeepalive = 25"]
        if wg.endpoint: body.append(f"Endpoint = {wg.endpoint}")
        conf_path.write_text("\n".join(body) + "\n"); conf_path.chmod(0o600)
        self._run(["wg-quick", "up", str(conf_path)])
        nf = Path(f"/var/run/wireguard/{name}.name")
        wg.interface_name = nf.read_text().strip() if nf.exists() else name
        log.warning(f"WireGuard [{name}] up on {wg.interface_name} (self-ip={wg.address})")

    def add_host_route(self, ip: str, wg: WireGuardConfig):
        key = (ip, wg.address)
        with self._lock:
            if key in self._peer_routes: return
            self._peer_routes.add(key)
        r = self._run(["route", "add", "-host", ip, wg.address], check=False)
        with self._lock:
            if r.returncode == 0: self._host_routes.append((ip, wg.interface_name))
            else: self._peer_routes.discard(key); log.debug(f"  host route {ip}: {r.stderr.strip()}")

    def stop_all(self):
        for ip, _ in list(self._host_routes):
            self._run(["route", "delete", "-host", ip], check=False)
        self._host_routes.clear(); self._peer_routes.clear()
        run_dir = Path.home() / ".config/woute/run"
        for name, wg in self.config.tunnels.items():
            if wg.interface_name:
                self._run(["wg-quick", "down", str(run_dir / f"{name}.conf")], check=False)
                wg.interface_name = ""
        log.warning("All WireGuard tunnels stopped")


# ── SOCKS5 ────────────────────────────────────────────────

async def socks5_handshake(reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> Optional[tuple]:
    try:
        ver, nmethods = await reader.readexactly(2)
        if ver != 5: writer.close(); return None
        await reader.readexactly(nmethods)
        writer.write(b"\x05\x00"); await writer.drain()

        req = await reader.readexactly(4)
        if req[0] != 5 or req[1] != 1:
            writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            await writer.drain(); writer.close(); return None

        atyp = req[3]
        if   atyp == 1: host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 3: host = (await reader.readexactly((await reader.readexactly(1))[0])).decode()
        elif atyp == 4: host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else: writer.close(); return None

        port = struct.unpack("!H", await reader.readexactly(2))[0]
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"); await writer.drain()
        return host, port
    except (asyncio.IncompleteReadError, ConnectionResetError):
        return None


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    total = 0
    try:
        while chunk := await reader.read(65536):
            total += len(chunk); writer.write(chunk); await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    except Exception as e:
        log.debug(f"pipe error after {total}B: {e}")
    finally:
        try: writer.close(); await writer.wait_closed()
        except OSError: pass


# ── Connection routing ────────────────────────────────────

def _resolve_via_tunnel(hostname: str, dns_ip: str, source: str) -> str:
    r = subprocess.run(["dig", "+short", "+time=5", "+tries=1", "-b", source,
                        f"@{dns_ip}", hostname, "A"],
                       capture_output=True, text=True, check=False)
    ips = [l for l in r.stdout.splitlines() if l and not l.startswith(";") and "." in l]
    if not ips: raise ConnectionError(f"No A record for {hostname}")
    return ips[0]


async def connect_via_wireguard(wg: WireGuardConfig, mgr: WireGuardManager,
                                 host: str, port: int):
    loop = asyncio.get_running_loop()
    dns_ip = next((s for s in wg.dns_servers or mgr.config.dns_servers if s), "1.1.1.1")
    mgr.add_host_route(dns_ip, wg)
    try:
        ip = await loop.run_in_executor(None, _resolve_via_tunnel, host, dns_ip, wg.address)
        log.debug(f"DNS via tunnel {wg.name} ({dns_ip}): {host} → {ip}")
    except Exception as e:
        log.debug(f"tunneled DNS failed ({e}), falling back to local resolver — DNS will leak")
        ip = await loop.run_in_executor(None, socket.gethostbyname, host)
    mgr.add_host_route(ip, wg)
    return await asyncio.wait_for(
        asyncio.open_connection(ip, port, local_addr=(wg.address, 0)), timeout=30)


async def _route_connection(cr: asyncio.StreamReader, cw: asyncio.StreamWriter,
                             host: str, port: int,
                             config: Config, wg_manager: Optional[WireGuardManager]):
    action, wg = await match_rule(host, port, config)
    _record(action, host, wg)
    try:
        if action == "block":
            log.warning(f"BLOCK     {host}:{port}"); cw.close(); return
        if action == "direct":
            log.debug(f"DIRECT    {host}:{port}")
            rr, rw = await asyncio.open_connection(host, port)
        else:
            if not wg or not wg.interface_name or not wg_manager:
                log.error(f"Tunnel '{wg.name if wg else '?'}' not running"); cw.close(); return
            log.info(f"WIREGUARD {host}:{port} → {wg.name} ({wg.interface_name})")
            rr, rw = await connect_via_wireguard(wg, wg_manager, host, port)
        await asyncio.gather(pipe(cr, rw), pipe(rr, cw), return_exceptions=True)
    except (ConnectionRefusedError, OSError, asyncio.TimeoutError) as e:
        log.warning(f"Connection error {host}:{port}: {e}")
    finally:
        try: cw.close(); await cw.wait_closed()
        except OSError: pass


async def handle_connection(cr: asyncio.StreamReader, cw: asyncio.StreamWriter,
                             config: Config, wg_manager: Optional[WireGuardManager] = None):
    result = await socks5_handshake(cr, cw)
    if result:
        await _route_connection(cr, cw, *result, config, wg_manager)


# ── Tunnel monitor ────────────────────────────────────────

async def tunnel_monitor(config: Config):
    while True:
        for name, wg in config.tunnels.items():
            age = _handshake_age(wg.interface_name)
            up, ts = age is not None and age <= 180, time.strftime("%H:%M:%S")
            with _state_lock:
                _tun_status[name] = [wg.interface_name or "", up, wg.address, wg.endpoint]
                _hb[name] = [ts, up]
        await asyncio.sleep(5)


# ── SIGHUP reload ─────────────────────────────────────────

_reload_flag = threading.Event()

def _sighup_handler(signum, frame):
    _reload_flag.set()

async def _reload_watcher(config: Config):
    while True:
        await asyncio.sleep(1)
        if _reload_flag.is_set():
            _reload_flag.clear()
            try:
                new = parse_config(CONF_PATH)
                config.rules         = new.rules
                config.tunnel_groups = new.tunnel_groups
                log.warning(f"Reloaded: {len(new.rules)} rules, {len(new.tunnel_groups)} groups")
            except Exception as e:
                log.error(f"Config reload failed: {e}")


# ── Log setup ─────────────────────────────────────────────

def _setup_logging(level: str, retention_days: int):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    p = LOG_DIR / f"woute-{time.strftime('%Y%m%d')}.log"
    h = logging.FileHandler(p)
    h.setFormatter(logging.Formatter(_FMT, datefmt=_DFMT))
    logging.getLogger().addHandler(h)
    if retention_days > 0:
        subprocess.run(["find", str(LOG_DIR), "-name", "woute-*.log",
                        "-mtime", f"+{retention_days}", "-delete"], check=False)
    logging.getLogger().setLevel(getattr(logging, level, logging.INFO))
    log.info(f"Logging to: {p}")


# ── Async core ────────────────────────────────────────────

async def main_async(config: Config, wg_manager: Optional[WireGuardManager], conf_path):
    loop = asyncio.get_running_loop()

    def _exc_handler(loop, ctx):
        exc = ctx.get("exception")
        if isinstance(exc, OSError) and exc.errno == 24:
            log.error("fd limit reached — shutting down"); loop.stop(); return
        loop.default_exception_handler(ctx)
    loop.set_exception_handler(_exc_handler)

    stop = asyncio.Event()
    loop.add_signal_handler(signal.SIGTERM, stop.set)

    server = await asyncio.start_server(
        lambda r, w: handle_connection(r, w, config, wg_manager),
        config.listen_host, config.listen_port)
    addr = server.sockets[0].getsockname()
    log.warning(f"woute v{VERSION}  SOCKS5 {addr[0]}:{addr[1]}")
    log.warning(f"{len(config.tunnels)} tunnel(s), {len(config.rules)} rule(s)")

    _sys_proxy(config.listen_host, config.listen_port)
    started_ts = time.time()
    try:
        asyncio.create_task(tunnel_monitor(config))
        asyncio.create_task(_state_dumper(config, conf_path, started_ts))
        asyncio.create_task(_reload_watcher(config))
        async with server:
            await stop.wait()
    except asyncio.CancelledError:
        pass
    finally:
        _sys_proxy()
        if wg_manager: wg_manager.stop_all()
        try: STATE_FILE.unlink(missing_ok=True)
        except OSError: pass


# ── Connection test ───────────────────────────────────────

async def _pick_sample(pattern: str) -> Optional[str]:
    if pattern in ("*", "default") or "/" in pattern: return None
    if "*" in pattern and not pattern.startswith("*."): return None
    if not pattern.startswith("*."): return pattern
    apex = pattern[2:]
    if not apex: return None
    loop = asyncio.get_running_loop()
    for c in (f"www.{apex}", f"api.{apex}", f"app.{apex}", f"mail.{apex}", apex):
        try:
            await asyncio.wait_for(loop.getaddrinfo(c, None, type=socket.SOCK_STREAM), 2.0)
            return c
        except Exception: continue
    return None


def _handshake_age(iface: str) -> Optional[int]:
    if not iface: return None
    r = subprocess.run(["wg", "show", iface, "latest-handshakes"],
                       capture_output=True, text=True, check=False)
    parts = r.stdout.strip().split() if r.returncode == 0 else []
    try: ts = int(parts[1]) if len(parts) >= 2 else 0
    except ValueError: return None
    return int(time.time() - ts) if ts else None


async def _probe(host: str, port: int, rule: Rule, sample: str, timeout: float = 5.0):
    p = await asyncio.create_subprocess_exec(
        "curl", "-sS", "-o", "/dev/null", "-m", str(timeout),
        "--socks5-hostname", f"{host}:{port}", f"https://{sample}",
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    await p.wait()
    ok = p.returncode == 0
    if rule.action == "block": return (not ok), (None if not ok else "not blocked")
    return ok, (None if ok else f"curl exit {p.returncode}")


async def _run_connection_tests(config: Config) -> bool:
    if not config.rules:
        print("  no rules configured — skipping test"); return True
    host, port = config.listen_host, config.listen_port
    ages = {n: _handshake_age(wg.interface_name) for n, wg in config.tunnels.items()}
    samples = await asyncio.gather(*(_pick_sample(r.value) for r in config.rules))

    tnames, groups = [], {}
    for i, r in enumerate(config.rules):
        t = None
        if r.action == "route" and r.target:
            for c in config.tunnel_groups.get(r.target, [r.target]):
                if c in config.tunnels: t = c; break
        tnames.append(t)
        groups.setdefault(t or f"__{r.action}__", []).append(i)

    results: dict = {}
    async def _group(idxs):
        for i in idxs:
            r, s, t = config.rules[i], samples[i], tnames[i]
            if s:
                results[i] = await _probe(host, port, r, s)
            elif r.action == "route" and t:
                age = ages.get(t); ok = age is not None and age <= 180
                results[i] = (ok, None if ok else ("no handshake" if age is None else f"stale {age}s"))
            else:
                results[i] = (None, None)
    await asyncio.gather(*(_group(idxs) for idxs in groups.values()))

    rows = []
    for i, r in enumerate(config.rules):
        ok, err = results[i]
        age = ages.get(tnames[i]) if tnames[i] else None
        act = f"{r.target} ({age}s)" if r.action == "route" and age is not None else (r.target or r.action)
        st = "skip" if ok is None else "pass" if ok else f"fail: {err}"
        rows.append((r.value, act, samples[i] or "—", st))

    w = [max(len(h), *(len(x[i]) for x in rows)) for i, h in enumerate(("rule", "action", "sample"))]
    print("\nConnection test:")
    print(f"  {'rule':<{w[0]}}  {'action':<{w[1]}}  {'sample':<{w[2]}}  status")
    for x in rows:
        print(f"  {x[0]:<{w[0]}}  {x[1]:<{w[1]}}  {x[2]:<{w[2]}}  {x[3]}")
    fails = sum(1 for x in rows if x[3].startswith("fail"))
    skips = sum(1 for x in rows if x[3] == "skip")
    if fails or skips:
        print(f"  ({len(rows)-fails-skips} pass, {fails} fail, {skips} skip)")
    return fails == 0


# ── Commands ──────────────────────────────────────────────

def main_start(fg: bool, run_tests: bool = True):
    if os.geteuid() != 0: sys.exit("woute: sudo required. Try: sudo woute start")
    if not CONF_PATH.exists():
        sys.exit(f"woute: config not found: {CONF_PATH}\nRun install.sh to create a template.")

    state, alive = {}, False
    if STATE_FILE.exists():
        try: state = json.loads(STATE_FILE.read_text())
        except Exception: pass
        if (pid := state.get("pid") or 0) > 0:
            try: os.kill(pid, 0); alive = True
            except ProcessLookupError: pass
            except OSError: alive = True

    if alive:
        print("woute: already running — testing existing proxy")
        if not run_tests: sys.exit(0)
        config = parse_config(CONF_PATH)
        for n, wg in config.tunnels.items():
            st = state.get("tunnel_status", {}).get(n)
            if st: wg.interface_name = st[0]
        try: ok = asyncio.run(_run_connection_tests(config))
        except KeyboardInterrupt: print("\nwoute: test aborted"); sys.exit(130)
        sys.exit(0 if ok else 1)

    if STATE_FILE.exists():
        _sys_proxy()
        STATE_FILE.unlink(missing_ok=True)

    config = parse_config(CONF_PATH)
    _setup_logging(config.log_level, config.log_retention_days)
    signal.signal(signal.SIGHUP, _sighup_handler)

    wg_manager = None
    if config.tunnels:
        wg_manager = WireGuardManager(config)
        try: wg_manager.start_all()
        except RuntimeError as e: log.error(str(e)); sys.exit(1)

    if not fg:
        print(f"woute: starting daemon (state → {STATE_FILE})")
        if os.fork() > 0:
            if not run_tests: sys.exit(0)
            try: sys.exit(0 if asyncio.run(_run_connection_tests(config)) else 1)
            except KeyboardInterrupt:
                print("\nwoute: test aborted (daemon still running)"); sys.exit(130)
        os.setsid()
        if os.fork() > 0: os._exit(0)
        sys.stdin = open(os.devnull, 'r')

    async def _run():
        if fg and run_tests: asyncio.create_task(_run_connection_tests(config))
        await main_async(config, wg_manager, CONF_PATH)
    try: asyncio.run(_run())
    except KeyboardInterrupt: log.info("Shutting down")


def cmd_stop():
    if not STATE_FILE.exists():
        sys.exit("woute: not running (no state file)")
    try: data = json.loads(STATE_FILE.read_text())
    except Exception as e: sys.exit(f"woute: can't read state: {e}")
    if not (pid := data.get("pid")): sys.exit("woute: no pid in state file")
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"woute: stopped (pid {pid})")
    except ProcessLookupError:
        print("woute: process already gone")
        try: STATE_FILE.unlink(missing_ok=True)
        except OSError: pass
    except PermissionError:
        sys.exit(f"woute: can't signal pid {pid} (owned by another user) — try: sudo woute stop")


G, R, D, B, Z = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"
def _up(ok): return f"{G}▲{Z}" if ok else f"{R}▼{Z}"


def _status_render(d, alive, pid):
    lines = [f"\033[H\033[2J\033[3J{G}▲{Z}  {B}woute{Z} {VERSION}  "
             f"{_up(alive)} {D}pid {pid}  {d.get('updated','—')}{Z}",
             f"{D}config   {d.get('conf_path','—')}{Z}",
             f"{D}started  {d.get('started','—')}{Z}"]
    ts, hb = d.get("tunnel_status", {}), d.get("hb", {})
    if (tuns := d.get("tunnels", [])):
        lines.append(f"\n{B}Tunnels{Z}")
        for n in tuns:
            iface, up, addr, ep = ts.get(n) or ["", False, "", ""]
            hbi = hb.get(n) or ["—", None]
            up2 = alive and (hbi[1] if hbi[1] is not None else bool(up))
            lines.append(f"  {n:<12} {D}{iface or '—':<8}{Z}  {_up(up2)}  {addr:<16} {D}{ep}  {hbi[0]}{Z}")
    if (tg := d.get("tunnel_groups", {})):
        lines.append(f"\n{B}Tunnel Groups{Z}")
        for gn, ms in tg.items():
            parts = [f"{m} {_up(alive and bool((ts.get(m) or ['', False])[1]))}" for m in ms]
            lines.append(f"  {gn:<12} {' '.join(parts)}")
    if (rules := d.get("rules", [])):
        mw = max(len(r["value"]) for r in rules)
        lines.append(f"\n{B}Rules{Z} {D}({len(rules)}){Z}")
        for r in rules:
            dest = r["target"] if r["action"] == "route" and r["target"] else r["action"]
            lines.append(f"  {r['value']:<{mw}} {D}->{Z} {dest}")
    c = d.get("counters", {})
    lines.append(f"\n{B}Traffic{Z}  routed {G}{c.get('routed',0):,}{Z}  "
                 f"direct {c.get('direct',0):,}  blocked {R}{c.get('blocked',0):,}{Z}")
    if (rec := [r for r in d.get("recent", []) if r[1] == "WIREGUARD"]):
        lines.append(f"\n{B}Recent{Z}")
        for ts_r, lbl, host, tgt in rec[:20]:
            lines.append(f"  {D}{ts_r}{Z}  {G}{lbl:<9}{Z} {host}{D+'  → '+tgt+Z if tgt else ''}")
    lines.append(f"\n{D}t: test  q: quit{Z}")
    return "\n".join(lines)


def _status_run_test():
    if not CONF_PATH.exists(): return
    sys.stdout.write("\033[2J\033[H"); sys.stdout.flush()
    cfg = parse_config(CONF_PATH)
    try:
        ts = json.loads(STATE_FILE.read_text()).get("tunnel_status", {})
        for n, wg in cfg.tunnels.items():
            if n in ts: wg.interface_name = ts[n][0]
    except Exception: pass
    try: asyncio.run(_run_connection_tests(cfg))
    except KeyboardInterrupt: print("\ntest aborted")
    print(f"\n{D}press any key to continue...{Z}")
    os.read(sys.stdin.fileno(), 1)


def cmd_status():
    sys.stdout.write("\033[?1049h\033[?25l"); sys.stdout.flush()
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    tty.setcbreak(fd)
    try:
        while True:
            if not STATE_FILE.exists():
                print(f"\033[H\033[2J\033[3J▲  woute {VERSION}\n\nnot running")
            else:
                try: d = json.loads(STATE_FILE.read_text())
                except json.JSONDecodeError: d = None
                if d:
                    pid = d.get("pid", 0)
                    try: os.kill(pid, 0); alive = True
                    except ProcessLookupError: alive = False
                    except OSError: alive = True
                    print(_status_render(d, alive, pid))
            if select.select([sys.stdin], [], [], 1.0)[0]:
                ch = os.read(fd, 1)
                if ch == b't': _status_run_test()
                elif ch == b'q': break
    except KeyboardInterrupt: pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write("\033[?25h\033[?1049l"); sys.stdout.flush()


# ── CLI ───────────────────────────────────────────────────

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "start"
    if cmd == "start":    main_start("--fg" in sys.argv, run_tests="--no-test" not in sys.argv)
    elif cmd == "stop":   cmd_stop()
    elif cmd == "status": cmd_status()
    elif cmd == "-t" and len(sys.argv) > 2:
        if not CONF_PATH.exists(): sys.exit(f"woute: config not found: {CONF_PATH}")
        addr = sys.argv[2]
        host, _, port_s = addr.rpartition(":")
        host, port = (host or addr), (int(port_s) if port_s.isdigit() else 443)
        action, wg = asyncio.run(match_rule(host, port, parse_config(CONF_PATH)))
        print(f"{host}:{port}  →  {wg.name if action == 'route' and wg else action}")
    else:
        sys.exit("usage: woute {start [--fg] [--no-test] | stop | status | -t HOST[:PORT]}")


if __name__ == "__main__":
    main()
