#!/bin/bash
# woute installer for macOS

INSTALL_DIR="$HOME/.local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Color helpers ─────────────────────────────────────────────────────────────
if [ -t 1 ] && command -v tput &>/dev/null && tput colors &>/dev/null; then
    RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3)
    CYAN=$(tput setaf 6); BOLD=$(tput bold); RESET=$(tput sgr0)
else
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
fi

ok()   { echo -e "  ${GREEN}[✓]${RESET} $*"; }
fail() { echo -e "  ${RED}[✗]${RESET} $*"; }
opt()  { echo -e "  ${YELLOW}[~]${RESET} $*"; }
info() { echo -e "  ${CYAN}==>${RESET} $*"; }

# ── ASCII Banner ──────────────────────────────────────────────────────────────
show_banner() {
    local version
    version=$(grep -m1 '^VERSION' "$SCRIPT_DIR/woute.py" 2>/dev/null \
              | sed 's/.*"\(.*\)".*/\1/')
    [ -z "$version" ] && version="?"

    echo -e "${BOLD}${CYAN}"
    cat <<'BANNER'
  ██╗    ██╗ ██████╗ ██╗   ██╗████████╗███████╗
  ██║    ██║██╔═══██╗██║   ██║╚══██╔══╝██╔════╝
  ██║ █╗ ██║██║   ██║██║   ██║   ██║   █████╗
  ██║███╗██║██║   ██║██║   ██║   ██║   ██╔══╝
  ╚███╔███╔╝╚██████╔╝╚██████╔╝   ██║   ███████╗
   ╚══╝╚══╝  ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝
BANNER
    echo -e "${RESET}${CYAN}  macOS WireGuard traffic router${RESET}                              v${version}"
    echo
}

# ── Status checkers ───────────────────────────────────────────────────────────
BREW_PATH=""
PYTHON3_PATH=""
WG_GO_PATH=""
WG_TOOLS_PATH=""
SCRIPT_PATH=""
PLIST_PATH="/Library/LaunchDaemons/com.woute.plist"

check_all() {
    BREW_PATH=$(command -v brew 2>/dev/null || true)
    PYTHON3_PATH=$(command -v python3 2>/dev/null || true)
    WG_GO_PATH=$(command -v wireguard-go 2>/dev/null || true)
    WG_TOOLS_PATH=$(command -v wg 2>/dev/null || true)
    if [ -x "$INSTALL_DIR/woute" ]; then
        SCRIPT_PATH="$INSTALL_DIR/woute"
    else
        SCRIPT_PATH=""
    fi
}

# ── Status display ────────────────────────────────────────────────────────────
show_status() {
    check_all
    echo -e "${BOLD} Status:${RESET}"

    if [ -n "$BREW_PATH" ]; then
        ok "Homebrew         $BREW_PATH"
    else
        fail "Homebrew         not installed"
    fi

    if [ -n "$PYTHON3_PATH" ]; then
        ok "python3          $PYTHON3_PATH"
    else
        fail "python3          not installed"
    fi

    if [ -n "$WG_GO_PATH" ]; then
        ok "wireguard-go     $WG_GO_PATH"
    else
        fail "wireguard-go     not installed"
    fi

    if [ -n "$WG_TOOLS_PATH" ]; then
        ok "wireguard-tools  $WG_TOOLS_PATH"
    else
        fail "wireguard-tools  not installed"
    fi

    if [ -n "$SCRIPT_PATH" ]; then
        ok "woute            $SCRIPT_PATH"
    else
        fail "woute            not installed"
    fi

    if [ -f "$PLIST_PATH" ]; then
        ok "launch daemon    $PLIST_PATH"
    else
        opt "launch daemon    not installed"
    fi

    # PATH hint inline
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo
        echo -e "  ${YELLOW}PATH:${RESET} $INSTALL_DIR is not in \$PATH"
    fi
    echo
}

# ── Install functions ─────────────────────────────────────────────────────────
install_brew() {
    if [ -n "$BREW_PATH" ]; then
        ok "Homebrew is already installed at $BREW_PATH"; return
    fi
    echo -e "\n  Install Homebrew from https://brew.sh ? [y/N] \c"
    read -rn1 yn; echo
    case "$yn" in
        [Yy]*)
            info "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            # Add brew to PATH for Apple Silicon if needed
            if [ -f /opt/homebrew/bin/brew ]; then
                eval "$(/opt/homebrew/bin/brew shellenv)"
            fi
            ok "Homebrew installed."
            ;;
        *) echo "  Skipped." ;;
    esac
}

install_deps() {
    if [ -z "$BREW_PATH" ] && [ -z "$(command -v brew 2>/dev/null)" ]; then
        echo -e "\n  ${RED}Homebrew is required first. Run option 1.${RESET}"; return 1
    fi

    # python3
    if [ -z "$PYTHON3_PATH" ]; then
        info "Installing python3 via Homebrew..."
        brew install python
    else
        ok "python3 already installed"
    fi

    # wireguard
    if [ -z "$WG_GO_PATH" ] || [ -z "$WG_TOOLS_PATH" ]; then
        info "Installing wireguard-go and wireguard-tools..."
        brew install wireguard-go wireguard-tools
    else
        ok "wireguard-go and wireguard-tools already installed"
    fi

}

install_script() {
    if [ ! -f "$SCRIPT_DIR/woute.py" ]; then
        echo -e "\n  ${RED}woute.py not found in $SCRIPT_DIR${RESET}"; return 1
    fi

    mkdir -p "$INSTALL_DIR"

    info "Copying woute.py → $INSTALL_DIR/woute"
    cp "$SCRIPT_DIR/woute.py" "$INSTALL_DIR/woute"
    chmod +x "$INSTALL_DIR/woute"

    # Ensure shebang
    if ! head -1 "$INSTALL_DIR/woute" | grep -q "python3"; then
        sed -i '' '1s|^|#!/usr/bin/env python3\n|' "$INSTALL_DIR/woute"
    fi

    ok "woute installed to $INSTALL_DIR/woute"

    # Seed config on first install
    local conf_dir="$HOME/.config/woute"
    local conf_file="$conf_dir/woute.conf"
    mkdir -p "$conf_dir"
    if [ ! -f "$conf_file" ]; then
        if [ -f "$SCRIPT_DIR/sample.conf" ]; then
            cp "$SCRIPT_DIR/sample.conf" "$conf_file"
            ok "Config seeded → $conf_file"
            open -e "$conf_file"
            echo
            echo -e "  ${YELLOW}woute.conf opened in TextEdit — fill in your WireGuard keys"
            echo -e "  and rules, then run: sudo woute start${RESET}"
        else
            echo -e "  ${YELLOW}sample.conf not found — create $conf_file manually${RESET}"
        fi
    else
        ok "Config already exists: $conf_file"
    fi

    # PATH configuration
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo
        echo -e "  ${YELLOW}$INSTALL_DIR is not in your \$PATH.${RESET}"
        echo -e "  Add the following line to your shell config:"
        echo
        echo -e "    ${BOLD}export PATH=\"\$HOME/.local/bin:\$PATH\"${RESET}"
        echo
        echo -e "  Auto-append to ~/.zshrc now? [y/N] \c"
        read -rn1 yn; echo
        case "$yn" in
            [Yy]*)
                echo '' >> "$HOME/.zshrc"
                echo '# woute' >> "$HOME/.zshrc"
                echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc"
                ok "Appended to ~/.zshrc — restart your shell or run: source ~/.zshrc"
                ;;
            *) echo "  Skipped. Add it manually when ready." ;;
        esac
    fi

    echo
    echo -e "${BOLD} Usage:${RESET}"
    echo "   sudo woute start              # start daemon + run rule test"
    echo "   sudo woute start --fg         # start in foreground (for launchd)"
    echo "   sudo woute start --no-test    # skip rule test"
    echo "   woute status                  # live status; press t to re-test, q to quit"
    echo "   sudo woute stop               # stop daemon"
    echo "   woute -t www.example.com      # check which rule matches a host"
}

# ── Launch daemon ─────────────────────────────────────────────────────────────
install_daemon() {
    if [ -z "$SCRIPT_PATH" ]; then
        echo -e "\n  ${RED}woute is not installed. Run option 3 first.${RESET}"; return 1
    fi

    local conf_file="$HOME/.config/woute/woute.conf"
    if [ ! -f "$conf_file" ]; then
        echo -e "\n  ${RED}Config not found: $conf_file${RESET}"
        echo -e "  Run option 3 to install woute and seed the config first."; return 1
    fi

    info "Writing $PLIST_PATH"
    sudo tee "$PLIST_PATH" > /dev/null <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>             <string>com.woute</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_DIR}/woute</string>
    <string>start</string>
    <string>--fg</string>
  </array>
  <key>RunAtLoad</key>         <true/>
  <key>KeepAlive</key>         <true/>
  <key>StandardOutPath</key>   <string>/var/log/woute.log</string>
  <key>StandardErrorPath</key> <string>/var/log/woute.log</string>
</dict>
</plist>
PLIST

    sudo launchctl load "$PLIST_PATH"
    ok "Daemon installed and started"
    ok "Run 'woute status' to observe it  |  logs: /var/log/woute.log"
}

remove_daemon() {
    if [ ! -f "$PLIST_PATH" ]; then
        echo -e "\n  ${YELLOW}No launch daemon installed.${RESET}"; return
    fi
    sudo launchctl unload "$PLIST_PATH"
    sudo rm "$PLIST_PATH"
    ok "Launch daemon removed"
}

open_config() {
    local conf_file="$HOME/.config/woute/woute.conf"
    if [ ! -f "$conf_file" ]; then
        echo -e "\n  ${RED}Config not found: $conf_file${RESET}"
        echo -e "  Run option 3 to install woute first."; return
    fi
    open -e "$conf_file"
    ok "Opened $conf_file in TextEdit"
}

remove_all() {
    echo
    echo -e "  ${RED}${BOLD}Full uninstall — removes all woute files.${RESET}"
    echo -e "  ${YELLOW}Continue? [y/N] \c"
    read -rn1 yn; echo
    case "$yn" in [Yy]*) ;; *) echo "  Cancelled."; return ;; esac

    # Stop and remove daemon
    if [ -f "$PLIST_PATH" ]; then
        sudo launchctl unload "$PLIST_PATH" 2>/dev/null
        sudo rm -f "$PLIST_PATH"
        ok "Launch daemon removed"
    fi

    # Remove binary
    rm -f "$INSTALL_DIR/woute"
    ok "Removed $INSTALL_DIR/woute"

    # Remove PATH line from .zshrc
    if grep -q '# woute' "$HOME/.zshrc" 2>/dev/null; then
        sed -i '' '/# woute/d;/woute.*PATH/d' "$HOME/.zshrc"
        ok "Removed PATH line from ~/.zshrc"
    fi

    # Remove generated files (logs, run confs, state)
    rm -f "$HOME/.config/woute/state.json"
    rm -f "$HOME/.config/woute/woute-"*.log
    rm -rf "$HOME/.config/woute/run"
    ok "Removed logs, state, and generated WireGuard confs"

    # Prompt before removing woute.conf (contains WireGuard keys)
    local conf_file="$HOME/.config/woute/woute.conf"
    if [ -f "$conf_file" ]; then
        echo
        echo -e "  Remove $conf_file? (contains WireGuard private keys) [y/N] \c"
        read -rn1 yn; echo
        case "$yn" in
            [Yy]*) rm -f "$conf_file"; ok "Removed $conf_file" ;;
            *)     opt "Kept $conf_file" ;;
        esac
    fi

    echo
    ok "Uninstall complete"
}

# ── Menu loop ─────────────────────────────────────────────────────────────────
show_menu() {
    echo -e "${BOLD} Options:${RESET}"
    echo "   1) Install Homebrew"
    echo "   2) Install dependencies  (python3, wireguard-go, wireguard-tools)"
    echo "   3) Install woute script + configure PATH"
    echo "   4) Full install          (steps 1 → 3)"
    echo "   5) Install launch daemon (auto-start on boot)"
    echo "   6) Remove launch daemon"
    echo "   7) Open config for editing"
    echo "   8) Full uninstall"
    echo "   q) Quit"
    echo
    echo -e " Choose an option: \c"
}

main() {
    clear
    show_banner

    while true; do
        show_status
        show_menu
        read -rn1 choice; echo

        case "$choice" in
            1)  install_brew ;;
            2)  install_deps ;;
            3)  install_script ;;
            4)  install_brew && install_deps && install_script ;;
            5)  install_daemon ;;
            6)  remove_daemon ;;
            7)  open_config ;;
            8)  remove_all ;;
            q|Q) echo -e " ${CYAN}Bye!${RESET}"; echo; exit 0 ;;
            *)  echo -e "  ${YELLOW}Invalid option.${RESET}" ;;
        esac

        echo
        echo -e "  Press any key to return to the menu... \c"
        read -rn1 -s
        clear
        show_banner
    done
}

main
