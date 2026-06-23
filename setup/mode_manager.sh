#!/bin/bash
# DefenderPi dynamic toggle script — AP + NAT + DHCP with Pi-hole integration
# Works for wlan1 AP (5GHz / 2.4GHz) and Monitor Mode
# Enhanced: waits for uplink before applying NAT; idempotent iptables, hostapd/dnsmasq ordering.

set -euo pipefail

DNSMASQ_DIR="/etc/dnsmasq.d"
FW_SCRIPT="/usr/local/sbin/defender-firewall-apply.sh"

# configurable wait (seconds) for uplink at runtime or via environment
MAX_WAIT_UPLINK="${MAX_WAIT_UPLINK:-90}"   # default 90s; export MAX_WAIT_UPLINK to change

log() { echo "[defenderpi-toggle] $*" >&2; }

start_dhcp_detection() {
    local iface=$1
    log "Starting DHCP detection services for $iface..."

    sudo systemctl stop dhcpdump@"$iface".service dhcp-json@"$iface".service dhcp-detector.service 2>/dev/null || true
    sleep 2

    sudo systemctl start dhcpdump@"$iface".service 2>/dev/null || true
    sudo systemctl start dhcp-json@"$iface".service 2>/dev/null || true
    sudo systemctl start dhcp-detector.service 2>/dev/null || true
}

stop_dhcp_detection() {
    local iface=$1
    log "Stopping DHCP detection services for $iface..."
    sudo systemctl stop dhcpdump@"$iface".service dhcp-json@"$iface".service dhcp-detector.service 2>/dev/null || true
}

reset_if() {
    local iface=$1
    log "Resetting interface $iface..."
    sudo ip addr flush dev "$iface"
    sudo ip link set "$iface" down
    sudo airmon-ng stop "$iface" >/dev/null 2>&1 || true
    sudo systemctl stop wpa_supplicant@"$iface".service 2>/dev/null || true
    sleep 1
    sudo ip link set "$iface" up
}

# idempotent iptables helpers (avoid duplicates)
iptables_add_once() {
    # usage: iptables_add_once -A ...
    if ! sudo iptables -C "$@" 2>/dev/null; then
        sudo iptables "$@"
    fi
}
iptables_nat_add_once() {
    if ! sudo iptables -t nat -C "$@" 2>/dev/null; then
        sudo iptables -t nat "$@"
    fi
}

# detect uplink now (eth0 or wlan0)
detect_uplink_now() {
    if ip -4 addr show dev eth0 2>/dev/null | grep -q "inet "; then echo "eth0"; return 0; fi
    if ip -4 addr show dev wlan0 2>/dev/null | grep -q "inet "; then echo "wlan0"; return 0; fi
    echo "none"
}

# detect uplink with wait up to MAX_WAIT_UPLINK
detect_uplink_wait() {
    local waited=0
    local step=2
    local uplink
    uplink="$(detect_uplink_now)"
    while [ "$uplink" = "none" ] && [ "$waited" -lt "$MAX_WAIT_UPLINK" ]; do
        log "No uplink yet — waiting (${waited}/${MAX_WAIT_UPLINK}s)..."
        sleep $step
        waited=$((waited + step))
        uplink="$(detect_uplink_now)"
    done
    echo "$uplink"
}

wait_for_service_active() {
    local svc=$1
    local timeout=${2:-15}
    local waited=0
    while [ $waited -lt $timeout ]; do
        if sudo systemctl is-active --quiet "$svc"; then
            return 0
        fi
        sleep 1
        waited=$((waited+1))
    done
    return 1
}

# -------------------------
# MAIN
# -------------------------

# Detect initial uplink (may be none)
uplink="none"
if ip addr show eth0 | grep -q "inet "; then uplink="eth0"; fi
if [ "$uplink" = "none" ] && ip addr show wlan0 | grep -q "inet "; then uplink="wlan0"; fi
log "Initial uplink interface: $uplink"

# Determine mode: interactive as before, but if no tty (boot), allow default selection or piped input
mode=""
# if first arg present, use it
if [ "${1:-}" != "" ]; then
    mode="$1"
fi

# if script is non-interactive and nothing piped, or service pipes '1', read will still work because systemd pipes '1\n' into it.
if [ -z "$mode" ]; then
    # if stdin is not a terminal (i.e. running under systemd with printf piping), read will pick up the piped value
    if [ -t 0 ]; then
        echo "Choose mode:"
        echo "1: wlan1 AP (5GHz, unified DHCP) - $uplink uplink"
        echo "2: wlan1 AP (2.4GHz, unified DHCP) - $uplink uplink"
        echo "3: Monitor Mode (wlan1)"
        read -p "Enter mode number: " mode
    else
        # non-interactive: default to 1 (wlan1 5GHz) if nothing piped
        # attempt to read any piped input with timeout, else default to 1
        if read -t 0.5 -r mode 2>/dev/null; then
            mode="${mode}"
        else
            mode="1"
            log "Non-interactive environment — defaulting to mode 1 (wlan1 5GHz)"
        fi
    fi
fi

# Stop running APs to ensure clean state
sudo systemctl stop hostapd@wlan1-2g.service hostapd@wlan1-5g.service hostapd@wlan0.service 2>/dev/null || true
sudo rm -f "$DNSMASQ_DIR/enabled.conf" 2>/dev/null || true

# Ensure IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

case "$mode" in
    1|2)
        ap_if="wlan1"
        reset_if "$ap_if"

        # wait for uplink (this avoids creating NAT with -o none)
        # if you don't want to wait, export MAX_WAIT_UPLINK=0 before running; if 0, skip wait.
        if [ "${MAX_WAIT_UPLINK:-0}" -gt 0 ]; then
            log "Waiting up to ${MAX_WAIT_UPLINK}s for uplink..."
            uplink="$(detect_uplink_wait)"
            log "Uplink after wait: $uplink"
        else
            uplink="$(detect_uplink_now)"
            log "MAX_WAIT_UPLINK=0: skipping wait; uplink now: $uplink"
        fi

        # Assign AP IP and bring up interface
        sudo ip addr add 192.168.50.1/24 dev "$ap_if" || true
        sudo ip link set dev "$ap_if" up

        # DHCP config for AP subnet
        sudo ln -sf "$DNSMASQ_DIR/$ap_if.conf" "$DNSMASQ_DIR/enabled.conf"

        # Start hostapd first and wait briefly to let hardware initialize
        if [ "$mode" -eq 1 ]; then
            sudo systemctl start hostapd@wlan1-5g.service
            wait_for_service_active "hostapd@wlan1-5g.service" 15 || log "hostapd@wlan1-5g not active yet (continue anyway)"
        else
            sudo systemctl start hostapd@wlan1-2g.service
            wait_for_service_active "hostapd@wlan1-2g.service" 15 || log "hostapd@wlan1-2g not active yet (continue anyway)"
        fi

        # Start/Restart dnsmasq AFTER hostapd so dnsmasq can bind to the AP interface
        sudo systemctl restart dnsmasq

        # Open DHCP ports early (idempotent insertion)
        sudo iptables -C INPUT -i "$ap_if" -p udp --dport 67 -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -i "$ap_if" -p udp --dport 67 -j ACCEPT

        # Ensure DNS ports allowed to/from Pi
        sudo iptables -C INPUT -i "$ap_if" -p udp --dport 53 -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -i "$ap_if" -p udp --dport 53 -j ACCEPT
        sudo iptables -C INPUT -i "$ap_if" -p tcp --dport 53 -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -i "$ap_if" -p tcp --dport 53 -j ACCEPT

        # NAT only — forwarding handled by defender-firewall-apply.sh
        if [ "$uplink" != "none" ]; then
            iptables_nat_add_once -A POSTROUTING -o "$uplink" -j MASQUERADE
            log "NAT applied for uplink $uplink"
        else
            log "No uplink available after wait — skipping NAT."
        fi

        # Start DHCP detection
        start_dhcp_detection "$ap_if"
        ;;

    3)
        ap_if="wlan1"
        stop_dhcp_detection "$ap_if"
        reset_if "$ap_if"
        sudo airmon-ng start "$ap_if"
        echo "Monitor mode active on ${ap_if}mon"
        ;;

    *)
        echo "Invalid option"
        exit 1
        ;;
esac

log "Mode $mode activated on interface $ap_if."
