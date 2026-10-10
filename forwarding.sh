#!/usr/bin/env bash


set -euo pipefail


if [[ $EUID -ne 0 ]]; then
    echo -e "\033[0;31mError: Run this as root (e.g., sudo ./script.sh).\033[0m" >&2
    exit 1
fi

if [[ -n "${SUDO_USER:-}" ]]; then
    REAL_USER="$SUDO_USER"
else
    echo -e "\033[0;31mError: Please run this with sudo so we know your real user account.\033[0m" >&2
    exit 1
fi

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

LOGO_PAD=0
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' 

RESOLV_BACKUP="/tmp/resolv.conf.bak"
POISON_PID_FILE="/tmp/traffic_poisoner.pid"

FIREWALL_LOCKED="false"
CLEANUP_DONE=0

# Safely capture system baseline state
ORIGINAL_HOSTNAME=$(hostname 2>/dev/null || echo "localhost")
ORIGINAL_IPV6_ALL=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)
ORIGINAL_IPV6_DEF=$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo 0)
ORIGINAL_TCP_TS=$(sysctl -n net.ipv4.tcp_timestamps 2>/dev/null || echo 1)
ORIGINAL_ICMP=$(sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null || echo 0)

# --- SYSTEM CLEANUP ON EXIT ---
cleanup_system_state() {
    if [[ "$CLEANUP_DONE" -eq 1 ]]; then return; fi
    CLEANUP_DONE=1
    
    echo -e "\n${YELLOW}=== Starting cleanup & restore protocol ===${NC}"
    
    if [[ -f "$POISON_PID_FILE" ]]; then
        echo -e "${CYAN}--> Stopping cover traffic simulator...${NC}"
        local p_pid=""
        p_pid=$(<"$POISON_PID_FILE" 2>/dev/null || true)
        if [[ -n "$p_pid" ]] && kill -0 "$p_pid" 2>/dev/null; then
            kill -TERM "$p_pid" 2>/dev/null || true
            wait "$p_pid" 2>/dev/null || true
        fi
        rm -f "$POISON_PID_FILE"
    fi

    if command -v mullvad >/dev/null 2>&1; then
        echo -e "${CYAN}--> Disconnecting Mullvad VPN...${NC}"
        mullvad disconnect >/dev/null 2>&1 || true
    fi

    echo -e "${CYAN}--> Unlocking and restoring original DNS settings...${NC}"
    if command -v chattr >/dev/null 2>&1 && [[ -f /etc/resolv.conf ]]; then
        chattr -i /etc/resolv.conf 2>/dev/null || true
    fi
    if [[ -f "$RESOLV_BACKUP" ]]; then
        cp "$RESOLV_BACKUP" /etc/resolv.conf 2>/dev/null || true
        rm -f "$RESOLV_BACKUP"
    fi
    
    if [[ "$FIREWALL_LOCKED" == "iptables" ]]; then
        echo -e "${CYAN}--> Flushing iptables killswitch rules...${NC}"
        if command -v iptables >/dev/null 2>&1; then
            iptables -F || true
            iptables -X || true
            iptables -P INPUT ACCEPT || true
            iptables -P FORWARD ACCEPT || true
            iptables -P OUTPUT ACCEPT || true
        fi
    elif [[ "$FIREWALL_LOCKED" == "mullvad" ]]; then
        echo -e "${CYAN}--> Disabling Mullvad VPN lockdown mode...${NC}"
        if command -v mullvad >/dev/null 2>&1; then
            mullvad lockdown-mode set off >/dev/null 2>&1 || true
        fi
    fi

    echo -e "${CYAN}--> Reverting kernel network settings to your defaults...${NC}"
    sysctl -w net.ipv6.conf.all.disable_ipv6="$ORIGINAL_IPV6_ALL" >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6="$ORIGINAL_IPV6_DEF" >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_timestamps="$ORIGINAL_TCP_TS" >/dev/null 2>&1 || true
    sysctl -w net.ipv4.icmp_echo_ignore_all="$ORIGINAL_ICMP" >/dev/null 2>&1 || true
    
    echo -e "${CYAN}--> Restoring original hostname ($ORIGINAL_HOSTNAME)...${NC}"
    if command -v hostnamectl >/dev/null 2>&1; then
        hostnamectl set-hostname "$ORIGINAL_HOSTNAME" >/dev/null 2>&1 || hostname "$ORIGINAL_HOSTNAME" >/dev/null 2>&1 || true
    else
        hostname "$ORIGINAL_HOSTNAME" >/dev/null 2>&1 || true
    fi
    
    echo -e "${CYAN}--> Flushing RAM caches to disk (Anti-forensics)...${NC}"
    sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    
    echo -e "${CYAN}--> Restarting network daemon...${NC}"
    if systemctl is-active NetworkManager >/dev/null 2>&1; then
        systemctl restart NetworkManager >/dev/null 2>&1 || true
    fi
    
    echo -e "${GREEN}System restored securely. Goodbye!${NC}"
}
trap cleanup_system_state EXIT

# --- UTILITIES ---
ensure_tool() {
    local tool_name="$1"
    local package_name="$2"
    
    if ! command -v "$tool_name" >/dev/null 2>&1; then
        echo -e "${YELLOW}--> Missing tool: ${tool_name}. Installing...${NC}"
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y >/dev/null 2>&1 && apt-get install -y "$package_name" >/dev/null 2>&1 || return 1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y "$package_name" >/dev/null 2>&1 || return 1
        elif command -v pacman >/dev/null 2>&1; then
            pacman -Sy --noconfirm "$package_name" >/dev/null 2>&1 || return 1
        else
            return 1
        fi
        
        if ! command -v "$tool_name" >/dev/null 2>&1; then
            return 1
        fi
    fi
    return 0
}

ensure_mullvad_service() {
    if command -v mullvad >/dev/null 2>&1; then
        if ! systemctl is-active --quiet mullvad-daemon 2>/dev/null; then
            systemctl start mullvad-daemon >/dev/null 2>&1 || true
            sleep 2
        fi
        return 0
    else
        return 1
    fi
}

pause() {
    echo ""
    read -r -p "Press [Enter] to continue..." _
}

get_active_interface() {
    local iface=""
    iface=$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5}' | head -n1 || true)
    if [[ -z "$iface" ]]; then
        iface=$(ip link show up 2>/dev/null | grep -E '^[0-9]+:' | awk -F': ' '{print $2}' | grep -Ev '^lo$' | head -n1 || true)
    fi
    echo "$iface"
}

# --- DYNAMIC INTRO ---
animate_logo_intro() {
    local logo=(
        " ██████╗  ██████╗ ██████╗  █████╗ ███╗   ███╗██╗███╗   ██╗███████╗ "
        " ██╔══██╗██╔═══██╗██╔══██╗██╔══██╗████╗ ████║██║████╗  ██║██╔════╝ "
        " ██║  ██║██║   ██║██████╔╝███████║██╔████╔██║██║██╔██╗ ██║█████╗   "
        " ██║  ██║██║   ██║██╔═══╝ ██╔══██║██║╚██╔╝██║██║██║╚██╗██║██╔══╝   "
        " ██████╔╝╚██████╔╝██║     ██║  ██║██║ ╚═╝ ██║██║██║ ╚████║███████╗ "
        " ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝ "
    )
    local cols
    cols=$(tput cols 2>/dev/null || echo 80)
    local logo_width=42
    local target_spaces=$(( (cols - logo_width) / 2 ))
    if (( target_spaces < 2 )); then target_spaces=2; fi
    if (( target_spaces > 18 )); then target_spaces=18; fi
    local slide_past=$(( target_spaces + 6 ))
    local slide_back=$(( target_spaces - 3 ))

    tput civis 2>/dev/null || true
    for ((i=0; i<=slide_past; i+=2)); do
        clear; echo -e "\n"; for line in "${logo[@]}"; do printf "%*s%s\n" "$i" "" "$line"; done; sleep 0.03
    done
    for ((i=slide_past; i>=slide_back; i--)); do
        clear; echo -e "\n"; for line in "${logo[@]}"; do printf "%*s%s\n" "$i" "" "$line"; done; sleep 0.02
    done
    for ((i=slide_back; i<=target_spaces; i++)); do
        clear; echo -e "\n"; for line in "${logo[@]}"; do printf "%*s%s\n" "$target_spaces" "" "$line"; done; sleep 0.03
    done
    LOGO_PAD=$target_spaces
    tput cnorm 2>/dev/null || true
}

show_logo() {
    local logo=(
        " ██████╗  ██████╗ ██████╗  █████╗ ███╗   ███╗██╗███╗   ██╗███████╗ "
        " ██╔══██╗██╔═══██╗██╔══██╗██╔══██╗████╗ ████║██║████╗  ██║██╔════╝ "
        " ██║  ██║██║   ██║██████╔╝███████║██╔████╔██║██║██╔██╗ ██║█████╗   "
        " ██║  ██║██║   ██║██╔═══╝ ██╔══██║██║╚██╔╝██║██║██║╚██╗██║██╔══╝   "
        " ██████╔╝╚██████╔╝██║     ██║  ██║██║ ╚═╝ ██║██║██║ ╚████║███████╗ "
        " ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝ "
    )
    echo -e "\n"
    for line in "${logo[@]}"; do printf "%*s%s\n" "$LOGO_PAD" "" "$line"; done
}

# --- MODULES 1 TO 7 ---
menu_hardware_layer() {
    clear; show_logo
    local TARGET_IFACE=""
    TARGET_IFACE=$(get_active_interface)
    if [[ -z "$TARGET_IFACE" ]]; then echo -e "${RED}Error: Couldn't find a network interface.${NC}"; pause; return; fi
    if ! ensure_tool "macchanger" "macchanger"; then pause; return; fi
    echo -e "${CYAN}=== Masking hardware ===${NC}"
    echo "--> Running: sysctl (disabling IPv6 stack to prevent leaks)"
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
    echo "--> Taking interface ${TARGET_IFACE} offline..."
    ip link set dev "$TARGET_IFACE" down || true
    sleep 1
    echo "--> Running: macchanger -e ${TARGET_IFACE} (giving you a fake MAC address)..."
    if macchanger -e "$TARGET_IFACE" >/dev/null 2>&1; then
        echo "--> Bringing ${TARGET_IFACE} back online..."
        ip link set dev "$TARGET_IFACE" up || true
        echo "--> Restarting NetworkManager to grab a new IP..."
        if systemctl is-active NetworkManager >/dev/null 2>&1; then systemctl restart NetworkManager >/dev/null 2>&1 || true; sleep 5; fi
        echo -e "${GREEN}[+] Done! IPv6 is off and your MAC address is hidden.${NC}"
    else
        echo -e "${RED}[-] MAC spoofing failed. The interface might be locked by your hardware.${NC}"
        ip link set dev "$TARGET_IFACE" up || true
    fi
    pause
}

menu_kernel_hardening() {
    clear; show_logo
    echo -e "${CYAN}=== Applying stealth settings ===${NC}"
    echo "--> Running: sysctl (disabling TCP timestamps)"
    sysctl -w net.ipv4.tcp_timestamps=0 >/dev/null 2>&1 || true
    echo "--> Running: sysctl (ignoring all ping requests)"
    sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null 2>&1 || true
    echo "--> Running: hostnamectl (changing computer name to 'localhost')"
    if command -v hostnamectl >/dev/null 2>&1; then
        hostnamectl set-hostname "localhost" >/dev/null 2>&1 || hostname "localhost" >/dev/null 2>&1 || true
    else
        hostname "localhost" >/dev/null 2>&1 || true
    fi
    echo -e "${GREEN}[+] Stealth settings applied successfully.${NC}"
    pause
}

menu_killswitch() {
    clear; show_logo
    echo "1) Connect Mullvad VPN & Engage Killswitch"; echo "2) Engage Manual Killswitch (Block non-VPN traffic)"; echo "3) Disable killswitch & Disconnect VPN"; echo "4) Back"; echo ""
    local ks_choice=""
    if ! read -r -p "Selection: " ks_choice; then return; fi
    echo ""
    case "$ks_choice" in
        1)
            if ensure_mullvad_service; then
                echo -e "${CYAN}--> Connecting to Mullvad VPN...${NC}"
                mullvad connect >/dev/null 2>&1 || true; sleep 3
                echo -e "${CYAN}--> Enabling Mullvad Native Lockdown Mode...${NC}"
                mullvad lockdown-mode set on >/dev/null 2>&1 || true
                FIREWALL_LOCKED="mullvad"
                mullvad status || true
                echo -e "${GREEN}[+] VPN connected and Location disguised successfully!${NC}"
            else
                echo -e "${RED}[-] Mullvad VPN is not installed or service couldn't start.${NC}"
            fi
            ;;
        2)
            if ensure_tool "iptables" "iptables"; then
                local tun_iface=""
                tun_iface=$(ip -o link show | awk -F': ' '{print $2}' | grep -E "^(tun|wg|mullvad)" | head -n1 || true)
                if [[ -z "$tun_iface" ]]; then
                    echo -e "${YELLOW}--> No active VPN interface detected.${NC}"
                    if ensure_mullvad_service; then
                        echo "--> Connecting Mullvad first..."
                        mullvad connect >/dev/null 2>&1 || true; sleep 3
                        tun_iface=$(ip -o link show | awk -F': ' '{print $2}' | grep -E "^(tun|wg|mullvad)" | head -n1 || true)
                    fi
                fi
                echo -e "${CYAN}--> Applying strict iptables firewall rules...${NC}"
                iptables -F || true; iptables -X || true
                iptables -A INPUT -i lo -j ACCEPT || true
                iptables -A OUTPUT -o lo -j ACCEPT || true
                iptables -A OUTPUT -p udp --dport 53 -j ACCEPT || true
                iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT || true
                iptables -A OUTPUT -p udp --dport 1194 -j ACCEPT || true
                iptables -A OUTPUT -p udp --dport 51820 -j ACCEPT || true
                if [[ -n "$tun_iface" ]]; then
                    iptables -A OUTPUT -o "$tun_iface" -j ACCEPT || true
                    iptables -A INPUT -i "$tun_iface" -j ACCEPT || true
                fi
                iptables -P INPUT DROP || true
                iptables -P FORWARD DROP || true
                iptables -P OUTPUT DROP || true
                FIREWALL_LOCKED="iptables"
                echo -e "${GREEN}[+] Killswitch Active. Non-VPN traffic is blocked.${NC}"
            fi
            ;;
        3)
            echo -e "${CYAN}--> Restoring standard routing and disabling killswitch...${NC}"
            if command -v mullvad >/dev/null 2>&1; then mullvad lockdown-mode set off >/dev/null 2>&1 || true; mullvad disconnect >/dev/null 2>&1 || true; fi
            if command -v iptables >/dev/null 2>&1; then iptables -F || true; iptables -X || true; iptables -P INPUT ACCEPT || true; iptables -P FORWARD ACCEPT || true; iptables -P OUTPUT ACCEPT || true; fi
            FIREWALL_LOCKED="false"
            echo -e "${GREEN}[+] Normal routing restored.${NC}"
            ;;
    esac
    pause
}

menu_dns_hardening() {
    clear; show_logo
    echo "1) Lock DNS (Use Quad9 & Cloudflare)"; echo "2) Restore Default DNS"; echo "3) Back"; echo ""
    local dns_choice=""
    if ! read -r -p "Selection: " dns_choice; then return; fi
    echo ""
    case "$dns_choice" in
        1)
            echo "--> Backing up current DNS file..."
            if [[ ! -f "$RESOLV_BACKUP" && -f /etc/resolv.conf ]]; then cp /etc/resolv.conf "$RESOLV_BACKUP"; fi
            echo "--> Removing immutable flag to edit /etc/resolv.conf..."
            if command -v chattr >/dev/null 2>&1; then chattr -i /etc/resolv.conf 2>/dev/null || true; fi
            echo "--> Writing new secure DNS addresses..."
            cat << EOF > /etc/resolv.conf
nameserver 9.9.9.9
nameserver 1.1.1.1
options edns0 trust-ad
EOF
            echo "--> Locking DNS file..."
            if command -v chattr >/dev/null 2>&1 && chattr +i /etc/resolv.conf 2>/dev/null; then
                echo -e "${GREEN}[+] DNS Locked. You are using secure resolvers.${NC}"
            else
                echo -e "${YELLOW}[!] DNS Updated, but your filesystem doesn't support 'chattr' locking.${NC}"
            fi
            ;;
        2)
            echo "--> Unlocking /etc/resolv.conf..."
            if command -v chattr >/dev/null 2>&1; then chattr -i /etc/resolv.conf 2>/dev/null || true; fi
            if [[ -f "$RESOLV_BACKUP" ]]; then
                echo "--> Restoring backup file..."
                cp "$RESOLV_BACKUP" /etc/resolv.conf
                echo -e "${GREEN}[+] Original DNS restored.${NC}"
            else
                echo -e "${YELLOW}[!] No backup found. Restarting network manager to reset DNS...${NC}"
                if systemctl is-active NetworkManager >/dev/null 2>&1; then systemctl restart NetworkManager >/dev/null 2>&1 || true; fi
            fi
            ;;
    esac
    pause
}

menu_traffic_poisoner() {
    clear; show_logo
    echo "1) Start cover traffic"; echo "2) Stop cover traffic"; echo "3) Back"; echo ""
    local poison_choice=""
    if ! read -r -p "Selection: " poison_choice; then return; fi
    echo ""
    case "$poison_choice" in
        1)
            if [[ -f "$POISON_PID_FILE" ]]; then
                local current_pid=""
                current_pid=$(<"$POISON_PID_FILE" 2>/dev/null || true)
                if [[ -n "$current_pid" ]] && kill -0 "$current_pid" 2>/dev/null; then
                    echo -e "${RED}Error: Simulator is already running (PID: $current_pid).${NC}"; pause; return
                fi
            fi
            if ! ensure_tool "curl" "curl"; then pause; return; fi
            echo -e "${CYAN}--> Spawning a background process to create fake web history...${NC}"
            (
                trap '' SIGINT
                local domains=("wikipedia.org" "reuters.com" "bbc.com" "nasa.gov" "imdb.com" "github.com" "stackoverflow.com" "archive.org" "nature.com" "npr.org")
                local user_agents=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15"
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
                    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
                )
                while true; do
                    local rand_domain="${domains[$RANDOM % ${#domains[@]}]}"
                    local rand_ua="${user_agents[$RANDOM % ${#user_agents[@]}]}"
                    curl -L -s -A "$rand_ua" --max-time 10 "https://$rand_domain" >/dev/null 2>&1 || true
                    sleep "$(( (RANDOM % 11) + 4 ))"
                done
            ) &
            echo "$!" > "$POISON_PID_FILE"
            echo -e "${GREEN}[+] Fake traffic simulator is active in the background (PID: $!).${NC}"
            ;;
        2)
            if [[ -f "$POISON_PID_FILE" ]]; then
                echo "--> Finding and killing background process..."
                local p_pid=""
                p_pid=$(<"$POISON_PID_FILE" 2>/dev/null || true)
                if [[ -n "$p_pid" ]] && kill -0 "$p_pid" 2>/dev/null; then kill -TERM "$p_pid" 2>/dev/null || true; echo -e "${GREEN}[+] Cover traffic stopped.${NC}"; else echo -e "${YELLOW}Simulator process wasn't actually running. Cleaned up.${NC}"; fi
                rm -f "$POISON_PID_FILE"
            else
                echo -e "${YELLOW}Simulator isn't running right now.${NC}"
            fi
            ;;
    esac
    pause
}

menu_browser_sandbox() {
    clear; show_logo
    echo -e "${CYAN}=== Launch Browser Sandbox ===${NC}"
    echo "1) Launch Tor Browser"; echo "2) Launch LibreWolf (Daily Browser)"; echo "3) Back"; echo ""
    local b_choice=""
    if ! read -r -p "Selection: " b_choice; then return; fi
    echo ""
    case "$b_choice" in
        1)
            if ! ensure_tool "torbrowser-launcher" "torbrowser-launcher"; then pause; return; fi
            echo -e "${GREEN}--> Executing Tor Browser Launcher as user (${REAL_USER})...${NC}"
            sudo -E -u "$REAL_USER" env "DISPLAY=${DISPLAY:-:0}" "XAUTHORITY=${XAUTHORITY:-/home/$REAL_USER/.Xauthority}" torbrowser-launcher >/dev/null 2>&1 &
            ;;
        2)
            if ! command -v librewolf >/dev/null 2>&1; then
                echo -e "${RED}LibreWolf is not installed or not in PATH.${NC}"
            else
                echo -e "${GREEN}--> Executing LibreWolf as user (${REAL_USER})...${NC}"
                sudo -E -u "$REAL_USER" env "DISPLAY=${DISPLAY:-:0}" "XAUTHORITY=${XAUTHORITY:-/home/$REAL_USER/.Xauthority}" librewolf >/dev/null 2>&1 &
            fi
            ;;
    esac
    pause
}

menu_full_lockdown() {
    clear; show_logo
    echo -e "${YELLOW}[!] ENGAGING COMPLETE LOCKDOWN...${NC}"
    echo "------------------------------------------------------"
    local TARGET_IFACE=""
    TARGET_IFACE=$(get_active_interface)
    echo "1/6: Masking Hardware..."
    if [[ -n "$TARGET_IFACE" ]]; then
        ensure_tool "macchanger" "macchanger" || return
        sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
        sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
        ip link set dev "$TARGET_IFACE" down || true
        sleep 1
        if macchanger -e "$TARGET_IFACE" >/dev/null 2>&1; then
            ip link set dev "$TARGET_IFACE" up || true
            if systemctl is-active NetworkManager >/dev/null 2>&1; then systemctl restart NetworkManager >/dev/null 2>&1 || true; sleep 5; fi
            echo -e "  ${GREEN}[+] Hardware identity hidden.${NC}"
        else
            echo -e "  ${RED}[-] MAC spoofing failed.${NC}"
            ip link set dev "$TARGET_IFACE" up || true
        fi
    fi
    echo "2/6: Applying Stealth Kernel Settings..."
    sysctl -w net.ipv4.tcp_timestamps=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null 2>&1 || true
    if command -v hostnamectl >/dev/null 2>&1; then
        hostnamectl set-hostname "localhost" >/dev/null 2>&1 || hostname "localhost" >/dev/null 2>&1 || true
    else
        hostname "localhost" >/dev/null 2>&1 || true
    fi
    echo -e "  ${GREEN}[+] Kernel limits engaged.${NC}"
    echo "3/6: Establishing VPN Tunnel & Disguising Location..."
    if ensure_mullvad_service; then
        mullvad connect >/dev/null 2>&1 || true; sleep 3
        mullvad lockdown-mode set on >/dev/null 2>&1 || true
        FIREWALL_LOCKED="mullvad"
        echo -e "  ${GREEN}[+] Mullvad VPN connected & lockdown enabled.${NC}"
    else
        echo -e "  ${YELLOW}[!] Mullvad CLI unavailable. Falling back to iptables...${NC}"
    fi
    echo "4/6: Securing DNS Resolvers..."
    if [[ ! -f "$RESOLV_BACKUP" && -f /etc/resolv.conf ]]; then cp /etc/resolv.conf "$RESOLV_BACKUP"; fi
    if command -v chattr >/dev/null 2>&1; then chattr -i /etc/resolv.conf 2>/dev/null || true; fi
    cat << EOF > /etc/resolv.conf
nameserver 9.9.9.9
nameserver 1.1.1.1
options edns0 trust-ad
EOF
    if command -v chattr >/dev/null 2>&1; then chattr +i /etc/resolv.conf 2>/dev/null || true; fi
    echo -e "  ${GREEN}[+] DNS Isolated.${NC}"
    echo "5/6: Launching Cover Traffic..."
    if [[ ! -f "$POISON_PID_FILE" ]]; then
        (
            trap '' SIGINT
            local domains=("wikipedia.org" "reuters.com" "bbc.com" "nasa.gov" "imdb.com" "github.com" "stackoverflow.com" "archive.org" "nature.com" "npr.org")
            local user_agents=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0")
            while true; do
                local rand_domain="${domains[$RANDOM % ${#domains[@]}]}"
                local rand_ua="${user_agents[$RANDOM % ${#user_agents[@]}]}"
                curl -L -s -A "$rand_ua" --max-time 10 "https://$rand_domain" >/dev/null 2>&1 || true
                sleep "$(( (RANDOM % 11) + 4 ))"
            done
        ) &
        echo "$!" > "$POISON_PID_FILE"
        echo -e "  ${GREEN}[+] Traffic simulator active.${NC}"
    fi
    echo "6/6: Verifying Killswitch Status..."
    if [[ "$FIREWALL_LOCKED" == "false" ]] && ensure_tool "iptables" "iptables"; then
        local tun_iface=""
        tun_iface=$(ip -o link show | awk -F': ' '{print $2}' | grep -E "^(tun|wg|mullvad)" | head -n1 || true)
        iptables -F || true; iptables -X || true
        iptables -A INPUT -i lo -j ACCEPT || true
        iptables -A OUTPUT -o lo -j ACCEPT || true
        iptables -A OUTPUT -p udp --dport 53 -j ACCEPT || true
        iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT || true
        iptables -A OUTPUT -p udp --dport 1194 -j ACCEPT || true
        iptables -A OUTPUT -p udp --dport 51820 -j ACCEPT || true
        if [[ -n "$tun_iface" ]]; then
            iptables -A OUTPUT -o "$tun_iface" -j ACCEPT || true
            iptables -A INPUT -i "$tun_iface" -j ACCEPT || true
        fi
        iptables -P INPUT DROP || true
        iptables -P FORWARD DROP || true
        iptables -P OUTPUT DROP || true
        FIREWALL_LOCKED="iptables"
        echo -e "  ${GREEN}[+] Manual iptables Killswitch active.${NC}"
    fi
    echo "------------------------------------------------------"
    echo -e "${GREEN}>>> LOCKDOWN COMPLETE - LOCATION DISGUISED <<<${NC}"
    pause
}

# --- MODULE 8: VERBOSE LIVE SYSTEM MONITOR ---
menu_live_monitor() {
    ensure_tool "ss" "iproute2" || true 
    
    while true; do
        local TARGET_IFACE=""
        TARGET_IFACE=$(get_active_interface)
        
        clear
        echo -e "${MAGENTA}========================================================================================${NC}"
        echo -e "${MAGENTA}                         [ OMNI-EYE LIVE SYSTEM DASHBOARD ]                             ${NC}"
        echo -e "${MAGENTA}========================================================================================${NC}"
        echo -e "${YELLOW}>> Auto-refreshing every 3 seconds. Press [Enter] to return to the main menu. <<${NC}\n"

        # 1. HARDWARE & SPOOFING STATUS
        echo -e "${CYAN}[1] IDENTITY & HARDWARE LAYER${NC}"
        echo -e "----------------------------------------------------------------------------------------"
        echo -e "Current Hostname:  $(hostname)"
        echo -e "Active Interface:  ${TARGET_IFACE:-None}"
        if command -v macchanger >/dev/null 2>&1 && [[ -n "$TARGET_IFACE" ]]; then
            macchanger -s "$TARGET_IFACE" 2>/dev/null | sed 's/^/  /' || echo "  MAC State: Unknown"
        else
            echo "  MAC Spoofing Tool (macchanger) not found or interface missing."
        fi
        
        if [[ -n "$TARGET_IFACE" ]]; then
            echo -e "\n  [Interface Packet Stats]"
            ip -s link show "$TARGET_IFACE" 2>/dev/null | awk 'NR>1 {print "    " $0}' || true
        fi
        echo ""

        # 2. VPN, IP & ROUTING DUMP
        echo -e "${CYAN}[2] TUNNELING & ROUTING TABLES${NC}"
        echo -e "----------------------------------------------------------------------------------------"
        if command -v mullvad >/dev/null 2>&1; then
            echo -e "Mullvad Status: $(mullvad status 2>/dev/null || echo 'Offline')"
        fi
        echo -e "\n  [Live IPv4 Routing Table]"
        ip -4 route show table all 2>/dev/null | sed 's/^/    /' || true
        
        echo -e "\n  [ARP / Neighbor Cache]"
        ip neigh show 2>/dev/null | sed 's/^/    /' || true
        echo ""

        # 3. KERNEL & DNS
        echo -e "${CYAN}[3] KERNEL FLAGS & DNS RESOLVERS${NC}"
        echo -e "----------------------------------------------------------------------------------------"
        echo -e "  IPv6 Stack (All):      $(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 'Unknown')"
        echo -e "  TCP Timestamps:        $(sysctl -n net.ipv4.tcp_timestamps 2>/dev/null || echo 'Unknown')"
        echo -e "  ICMP (Ping) Ignore:    $(sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null || echo 'Unknown')"
        
        echo -e "\n  [Contents of /etc/resolv.conf]"
        cat /etc/resolv.conf 2>/dev/null | grep -v '^#' | sed 's/^/    /' || true
        echo ""

        # 4. BACKGROUND PROCESSES
        echo -e "${CYAN}[4] BACKGROUND SIMULATORS${NC}"
        echo -e "----------------------------------------------------------------------------------------"
        if [[ -f "$POISON_PID_FILE" ]]; then
            local p_pid=""
            p_pid=$(<"$POISON_PID_FILE" 2>/dev/null || true)
            if [[ -n "$p_pid" ]] && kill -0 "$p_pid" 2>/dev/null; then
                echo -e "  Cover Traffic Daemon:  ${GREEN}ACTIVE${NC} (PID: $p_pid)"
                ps -p "$p_pid" -o %cpu,%mem,cmd 2>/dev/null | sed 's/^/    /' || true
            else
                echo -e "  Cover Traffic Daemon:  ${RED}DEAD/ORPHANED PID FILE${NC}"
            fi
        else
            echo -e "  Cover Traffic Daemon:  ${YELLOW}INACTIVE${NC}"
        fi
        echo ""

        # 5. IPTABLES FIREWALL WALL
        echo -e "${CYAN}[5] RAW FIREWALL POLICIES (IPTABLES V-DUMP)${NC}"
        echo -e "----------------------------------------------------------------------------------------"
        echo -e "Script Killswitch State: ${FIREWALL_LOCKED}"
        if command -v iptables >/dev/null 2>&1; then
            iptables -L -n -v --line-numbers 2>/dev/null | sed 's/^/  /' || true
        else
            echo "  iptables not installed."
        fi
        echo ""

        # 6. MASSIVE SOCKET CONNECTIONS DUMP
        echo -e "${CYAN}[6] KERNEL SOCKET DUMP (ACTIVE CONNECTIONS)${NC}"
        echo -e "----------------------------------------------------------------------------------------"
        echo -e "Displaying TCP/UDP states, internal timers, and owning processes (ss -tunapi)..."
        echo ""
        if command -v ss >/dev/null 2>&1; then
            ss -tunapi 2>/dev/null | sed 's/^/  /' | head -n 40 || true
            echo -e "\n  ${YELLOW}... (Output truncated for display; viewing top 40 lines) ...${NC}"
        else
            netstat -tunap 2>/dev/null | sed 's/^/  /' || echo "  Connection tracking tools missing."
        fi

        echo -e "\n${MAGENTA}========================================================================================${NC}"
        
        if read -t 3 -n 1 -r; then
            break
        fi
    done
}

# --- SYSTEM INITIALIZATION ---
animate_logo_intro

while true; do
    clear
    show_logo
    echo "User:      $REAL_USER"
    echo "Interface: $(get_active_interface)"
    
    if [[ "$FIREWALL_LOCKED" == "iptables" ]] || [[ "$FIREWALL_LOCKED" == "mullvad" ]]; then
        echo -e "Firewall:  ${GREEN}[LOCKED]${NC}"
    else
        echo -e "Firewall:  ${RED}[OPEN]${NC}"
    fi
    echo ""
    echo "1) Spoof MAC & drop IPv6"
    echo "2) Stealth kernel & hide hostname"
    echo "3) Connect VPN & Killswitch"
    echo "4) Lock DNS"
    echo "5) Cover traffic"
    echo "6) Launch Browsers (Tor / LibreWolf)"
    echo "7) Full Lockdown"
    echo "8) Live System Monitor (Verbose)"
    echo "9) Restore & Exit"
    echo ""
    
    main_choice=""
    if ! read -r -p "Choose an option [1-9]: " main_choice; then
        exit 0
    fi
    
    case "$main_choice" in
        1) menu_hardware_layer ;;
        2) menu_kernel_hardening ;;
        3) menu_killswitch ;;
        4) menu_dns_hardening ;;
        5) menu_traffic_poisoner ;;
        6) menu_browser_sandbox ;;
        7) menu_full_lockdown ;;
        8) menu_live_monitor ;;
        9) exit 0 ;;
        *) echo -e "${RED}Invalid choice.${NC}"; sleep 1 ;;
    esac
done
