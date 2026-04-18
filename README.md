```
  ██╗    ██╗ ██████╗ ██╗   ██╗████████╗███████╗
  ██║    ██║██╔═══██╗██║   ██║╚══██╔══╝██╔════╝
  ██║ █╗ ██║██║   ██║██║   ██║   ██║   █████╗
  ██║███╗██║██║   ██║██║   ██║   ██║   ██╔══╝
  ╚███╔███╔╝╚██████╔╝╚██████╔╝   ██║   ███████╗
   ╚══╝╚══╝  ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝
  macOS WireGuard traffic router                              v1.0.0
```

**Rule-based WireGuard traffic router for macOS.** A small SOCKS5 proxy that reads a plain-text config and, per connection, sends traffic through a named WireGuard tunnel, direct, or drops it.

Not a VPN. The tunnel is yours — woute just decides which traffic uses it.

The whole program is a single Python file. Read it before you run it with `sudo`.

Site: [woute.dev](https://woute.dev)

---

## What it looks like

`sudo woute start` brings up the tunnels, runs a rule test, and detaches. `woute status` shows a live dashboard:

```
▲  woute 1.0.0  ▲ pid 12345  14:02:07
config   /Users/harry/.config/woute/woute.conf
started  2026-04-18 13:59:20

Tunnels
  Taiwan       utun6     ▲  10.14.0.2        wg-tw.example.com:51820  14:02:07
  Japan        utun7     ▲  10.14.0.3        wg-jp.example.com:51820  14:02:07

Tunnel Groups
  VPN          Taiwan ▲  Japan ▲

Rules (7)
  127.0.0.0/8       -> direct
  10.0.0.0/8        -> direct
  192.168.0.0/16    -> direct
  *.ads.example.com -> block
  *tracker*         -> block
  *.example.com     -> VPN
  default           -> direct

Traffic  routed 284  direct 1,902  blocked 37

Recent
  14:03:12  WIREGUARD api.example.com  → Taiwan

t: test  q: quit
```

Press `t` to re-run the rule test against the running proxy; `q` or Ctrl-C to exit the dashboard (the daemon keeps running).

---

## Install

```sh
git clone https://github.com/harryngai/woute
cd woute && ./install.sh
```

The installer is a menu. It checks for and installs Homebrew, `python3`, `wireguard-go`, and `wireguard-tools`, then copies `woute.py` to `~/.local/bin/woute` and offers to append it to your `$PATH` via `~/.zshrc`.

---

## Run

```sh
sudo woute start              # bring up tunnels, run rule test, detach as daemon
sudo woute start --fg         # stay in foreground (for launchd)
sudo woute start --no-test    # skip the rule test
woute status                  # live dashboard; t to re-test, q to quit
sudo woute stop               # stop the daemon
woute -t www.example.com      # dry-run: which rule would match this host
```

`sudo` is required for `start` / `stop` — WireGuard needs to create `utun` interfaces and add routes. `status` and `-t` don't need sudo.

The daemon writes state to `~/.config/woute/state.json` every second. Run `woute status` from any terminal to observe it. The state file is deleted on clean shutdown, so `status` reports "not running" when nothing is running.

The rule test runs curl through the proxy for each rule — sampling `www.X` / apex for wildcards, probing each hostname rule; CIDR and mid-wildcard patterns are skipped. Pass/fail rows print to the terminal before the daemon detaches; use `--no-test` to skip.

To auto-start on boot, use the installer: `./install.sh` → option 5. It creates a launchd daemon at `/Library/LaunchDaemons/com.woute.plist` that starts woute as root at boot and restarts it if it crashes. Logs go to `/var/log/woute.log`.

---

## Config

A config has four section types. See `sample.conf` for a working starting point.

```ini
[General]
socks5-listen = 7890              # or 0.0.0.0:7890 to accept LAN
log-level     = warning           # debug | info | warning | error
log-retention = 7                 # days to keep daily logs; 0 = keep all
dns           = 1.1.1.1, 1.0.0.1  # fallback DNS for tunneled traffic

[Tunnel Group]
VPN = Taiwan, Japan               # tried in order; first with fresh handshake wins

[Tunnel: Taiwan]
private-key = YOUR_PRIVATE_KEY
address     = 10.14.0.2           # your local IP inside the tunnel (assigned by the peer)
dns         = 10.0.0.1            # optional; per-tunnel DNS (overrides [General] dns)
public-key  = PEER_PUBLIC_KEY
endpoint    = wg-tw.example.com:51820
allowed-ips = 0.0.0.0/0

[Rule]
*.example.com    -> VPN
192.168.0.0/16   -> direct
*tracker*        -> block
default          -> direct
```

Logs go to `~/.config/woute/logs/woute-YYYYMMDD.log`. Files older than `log-retention` days are pruned on every `woute start`.

**DNS for tunneled traffic** resolves through the tunnel itself — `dig -b <tunnel-address> @<dns-ip>`. The DNS server is picked per-connection: `[Tunnel: X] dns` if set, else `[General] dns`, else `1.1.1.1`. This prevents DNS queries (and hostnames) from leaking to your ISP for traffic the rule engine decided to route. `direct` and `block` rules still use the system resolver.

### Rules

Evaluated top-to-bottom, first match wins. Left side is what to match; right side is where to send.

| Pattern            | Matches                                   |
|--------------------|-------------------------------------------|
| `*.example.com`    | `example.com` and any subdomain           |
| `example.com`      | exact match only                          |
| `*keyword*`        | any host containing `keyword`             |
| `1.2.3.0/24`       | IPs in that CIDR (resolves the host first)|
| `default`          | catch-all — put last                      |

| Target        | Effect                                              |
|---------------|-----------------------------------------------------|
| `direct`      | Plain TCP, no tunnel                                |
| `block`       | Close the connection                                |
| *tunnel name* | Route via that `[Tunnel: name]`                     |
| *group name*  | Route via that `[Tunnel Group]` (fallback order)    |

### Tunnel groups

```ini
[Tunnel Group]
VPN = Taiwan, Japan, HongKong
```

Members are tried in config order. The first one with a WireGuard handshake newer than 180 seconds wins. If none are fresh, the first member is used anyway (better to try than to fail). Reorder in the config and send `SIGHUP` to the daemon to reload (`sudo kill -HUP $(cat ~/.config/woute/state.json | jq -r .pid)`).

---

## Architecture

All rule evaluation happens in-process. No external service, no phone-home. For the architecture diagram and full connection-sequence reference — startup, per-connection routing, rule test, status + background loops, shutdown, tunnel-group fallback — see [woute.dev](https://woute.dev).

---

## CLI

Config lives at `~/.config/woute/woute.conf`.

| Command                       | Description                                |
|-------------------------------|--------------------------------------------|
| `sudo woute start`            | Bring up tunnels, run rule test, detach    |
| `sudo woute start --fg`       | Stay in foreground (used by launchd)       |
| `sudo woute start --no-test`  | Skip the rule test                         |
| `sudo woute stop`             | Stop the daemon                            |
| `woute status`                | Live dashboard for a running daemon        |
| `woute -t <host>`             | Print which rule matches, don't start      |
| `woute -t <host>:<port>`      | Same, for a specific port (default 443)    |

---

## Status keys

Inside `woute status`:

| Key       | Action                                                        |
|-----------|---------------------------------------------------------------|
| `t`       | Re-run the rule test against the running proxy                |
| `q` / Ctrl-C | Exit the dashboard. Daemon keeps running.                  |

The test clears the screen, runs curl through the proxy for each rule (sampling `www.X` / apex for wildcards), prints a pass/fail table, then waits for any key to resume.

---

## Why

I already had WireGuard tunnels. I wanted per-domain rules where the config still makes sense six months later, and where the code handling my traffic was short enough to read before running it with `sudo`.

Alternatives are either unreadable (Clash YAML, sing-box JSON), closed (Surge), or both. woute is under 800 lines of Python. The config looks like what it does.

---

## Not for

- A single always-on tunnel with no per-domain rules — use `wg-quick`.
- Corporate VPN access — use your employer's client.
- Linux or Windows — macOS only.

---

MIT · macOS only · [woute.dev](https://woute.dev) · [harryngai/woute](https://github.com/harryngai/woute)
