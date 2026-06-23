#!/bin/bash
# Usage: defender-firewall-apply.sh <AP_IFACE> <UPLINK_IFACE> <AP_SUBNET>
# NOTE: Toggle script owns NAT + core forwarding.
# This script ONLY enforces DefenderPi security rules.

AP_IFACE=${1:-wlan1}
UPLINK_IFACE=${2}
AP_SUBNET=${3:-192.168.50.0/24}

# ------------------------------------------------------------------
# Resolve uplink safely (BOOT SAFE)
# ------------------------------------------------------------------

if [ -z "$UPLINK_IFACE" ] || [ "$UPLINK_IFACE" = "none" ]; then
    if ip -4 addr show eth0 2>/dev/null | grep -q "inet "; then
        UPLINK_IFACE="eth0"
    elif ip -4 addr show wlan0 2>/dev/null | grep -q "inet "; then
        UPLINK_IFACE="wlan0"
    else
        echo "[!] No valid uplink detected. Continuing without uplink rules."
        UPLINK_IFACE=""
    fi
fi

echo "[*] Applying DefenderPi AP firewall rules..."
echo "    AP_IFACE=$AP_IFACE, UPLINK_IFACE=${UPLINK_IFACE:-none}, SUBNET=$AP_SUBNET"

# ------------------------------------------------------------------
# HARD RESET CHAINS (DETERMINISTIC APPLIANCE MODE)
# ------------------------------------------------------------------

iptables -F INPUT
iptables -F FORWARD
iptables -F OUTPUT

iptables -P INPUT DROP
iptables -P FORWARD DROP

# ------------------------------------------------------------------
# DNS ENFORCEMENT (FORCE ALL CLIENT DNS TO PIHOLE)
# ------------------------------------------------------------------

iptables -t nat -C PREROUTING -i "$AP_IFACE" -p udp --dport 53 -j DNAT --to-destination 192.168.50.1:53 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$AP_IFACE" -p udp --dport 53 -j DNAT --to-destination 192.168.50.1:53

iptables -t nat -C PREROUTING -i "$AP_IFACE" -p tcp --dport 53 -j DNAT --to-destination 192.168.50.1:53 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$AP_IFACE" -p tcp --dport 53 -j DNAT --to-destination 192.168.50.1:53

# ------------------------------------------------------------------
# PORT FORWARDING (WAN → DVWA)
# ------------------------------------------------------------------

iptables -t nat -C PREROUTING -i "$UPLINK_IFACE" \
  -p tcp --dport 8080 \
  -j DNAT --to-destination 192.168.50.34:80 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$UPLINK_IFACE" \
  -p tcp --dport 8080 \
  -j DNAT --to-destination 192.168.50.34:80

iptables -t nat -C PREROUTING -i "$UPLINK_IFACE" \
  -p tcp --dport 8443 \
  -j DNAT --to-destination 192.168.50.34:443 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$UPLINK_IFACE" \
  -p tcp --dport 8443 \
  -j DNAT --to-destination 192.168.50.34:443

iptables -t nat -C PREROUTING -i "$UPLINK_IFACE" \
  -p tcp --dport 8021 \
  -j DNAT --to-destination 192.168.50.54:21 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$UPLINK_IFACE" \
  -p tcp --dport 8021 \
  -j DNAT --to-destination 192.168.50.54:21

# ------------------------------------------------------------------
# ENSURE REQUIRED IPSETS EXIST
# ------------------------------------------------------------------

ipset create defender_suricata hash:ip timeout 180 -exist
ipset create defender_suricata_perma hash:ip -exist
ipset create defender_gateway_protect hash:ip timeout 600 -exist
ipset create defender_network_quarantine hash:ip timeout 300 -exist
ipset create defender_ml_block hash:ip timeout 900 -exist
ipset create defender_ml_rate_limit hash:ip timeout 300 -exist

# ------------------------------------------------------------------
# INPUT HARDENING
# ------------------------------------------------------------------

iptables -I INPUT 1 -m set --match-set defender_gateway_protect src -j DROP
# 🔴 NETWORK QUARANTINE (LAN ATTACKS → GATEWAY PROTECTION)
iptables -I INPUT 2 -m set --match-set defender_network_quarantine src -j DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

iptables -A INPUT -i "$AP_IFACE" -p udp --dport 67 -j ACCEPT
iptables -A INPUT -i "$AP_IFACE" -p udp --dport 53 -d 192.168.50.1 -j ACCEPT
iptables -A INPUT -i "$AP_IFACE" -p tcp --dport 53 -d 192.168.50.1 -j ACCEPT

iptables -A INPUT -s "$AP_SUBNET" -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -s "$AP_SUBNET" -p tcp --dport 5900:5902 -j ACCEPT
iptables -A INPUT -s "$AP_SUBNET" -p tcp --dport 5000 -j ACCEPT
iptables -A INPUT -s "$AP_SUBNET" -p tcp --dport 3000 -j ACCEPT

iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

iptables -A INPUT -i "$AP_IFACE" -p tcp --syn -m limit --limit 30/second --limit-burst 60 -j ACCEPT
iptables -A INPUT -i "$AP_IFACE" -p tcp --syn -j DROP

# ------------------------------------------------------------------
# OUTPUT CHAIN (DNS VISIBILITY FOR SURICATA)
# ------------------------------------------------------------------

iptables -P OUTPUT ACCEPT

iptables -I OUTPUT 1 -p udp --dport 53 -m owner --uid-owner unbound -j NFQUEUE --queue-num 0
iptables -I OUTPUT 2 -p tcp --dport 53 -m owner --uid-owner unbound -j NFQUEUE --queue-num 0

iptables -A OUTPUT -p udp --dport 53 -m owner --uid-owner unbound -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -m owner --uid-owner unbound -j ACCEPT

iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -d 127.0.0.1 -j ACCEPT

iptables -A OUTPUT -p udp --dport 53 -j DROP
iptables -A OUTPUT -p tcp --dport 53 -j DROP

# ------------------------------------------------------------------
# FORWARD CHAIN (STRICT ZERO-LEAKAGE MODE)
# ------------------------------------------------------------------

# 🔴 1. ABSOLUTE BLOCK (TOP PRIORITY — ORDER GUARANTEED)

iptables -I FORWARD 1 -m set --match-set defender_network_quarantine src -j DROP
iptables -I FORWARD 2 -m set --match-set defender_ml_block src -j DROP
iptables -I FORWARD 3 -m set --match-set defender_suricata_perma src -j DROP
iptables -I FORWARD 4 -m set --match-set defender_suricata src -j DROP

if ipset list defender_badips >/dev/null 2>&1; then
    iptables -I FORWARD 5 -m set --match-set defender_badips src -j DROP
    iptables -I FORWARD 6 -m set --match-set defender_badips dst -j DROP
fi

# 🔴 2. NFQUEUE (ONLY AFTER HARD BLOCKS)
if [ -n "$UPLINK_IFACE" ]; then
    iptables -A FORWARD -i "$AP_IFACE" -o "$UPLINK_IFACE" \
      -j NFQUEUE --queue-num 0

    iptables -A FORWARD -i "$UPLINK_IFACE" -o "$AP_IFACE" \
      -j NFQUEUE --queue-num 0
fi

# 🔴 4. ML RATE LIMIT (STRONG VERSION)

# 4.1 HARD CAP concurrent connections (MUST BE FIRST)
iptables -A FORWARD -m set --match-set defender_ml_rate_limit src \
  -m connlimit --connlimit-above 20 --connlimit-mask 32 \
  -j DROP

# 4.2 RATE LIMIT (ALL PACKETS, not just NEW)
iptables -A FORWARD -m set --match-set defender_ml_rate_limit src \
  -m hashlimit --hashlimit 5/sec --hashlimit-burst 10 \
  --hashlimit-mode srcip --hashlimit-name dp_ml_rl \
  -j ACCEPT

# 4.3 FINAL DROP
iptables -A FORWARD -m set --match-set defender_ml_rate_limit src -j DROP

# 🔴 3. STATE HANDLING (AFTER INSPECTION)
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP

# 🔴 5. DNS ENFORCEMENT
iptables -A FORWARD -i "$AP_IFACE" ! -d 192.168.50.1 -p udp --dport 53 -j REJECT
iptables -A FORWARD -i "$AP_IFACE" ! -d 192.168.50.1 -p tcp --dport 53 -j REJECT

# ❗ NO FINAL ACCEPT — POLICY DROP HANDLES EVERYTHING ELSE



echo "[+] DefenderPi AP firewall applied (deterministic mode)."

