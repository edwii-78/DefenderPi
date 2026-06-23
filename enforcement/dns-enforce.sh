#!/bin/bash
# DefenderPi - DNS Enforcement Script
# Forces AP clients (wlan1) to use Pi-hole as DNS (port 53)

set -e
echo "[*] Applying DefenderPi DNS enforcement on wlan1..."

IFACE="wlan1"
AP_SUBNET="192.168.50.0/24"
PI_IP="192.168.50.1"
TRUSTED_UPSTREAMS="/etc/defenderpi/trusted_dns_servers"

# Cleanup existing chain if it exists
if iptables -t nat -L DEFENDERPI_DNS >/dev/null 2>&1; then
    iptables -t nat -F DEFENDERPI_DNS
    # Delete any existing PREROUTING jumps to DEFENDERPI_DNS
    for proto in udp tcp; do
        while iptables -t nat -C PREROUTING -i "$IFACE" -p $proto --dport 53 -j DEFENDERPI_DNS >/dev/null 2>&1; do
            iptables -t nat -D PREROUTING -i "$IFACE" -p $proto --dport 53 -j DEFENDERPI_DNS
        done
    done
else
    iptables -t nat -N DEFENDERPI_DNS
fi

# Hook into PREROUTING for UDP/TCP DNS from wlan1
for proto in udp tcp; do
    iptables -t nat -A PREROUTING -i "$IFACE" -p $proto --dport 53 -j DEFENDERPI_DNS
done

# Allow DNS queries directly to Pi itself
iptables -t nat -A DEFENDERPI_DNS -d "$PI_IP" -j RETURN

# Allow trusted upstream DNS servers (if any)
if [ -f "$TRUSTED_UPSTREAMS" ]; then
  while read -r ip; do
    [ -z "$ip" ] && continue
    iptables -t nat -A DEFENDERPI_DNS -d "$ip" -j RETURN
  done < "$TRUSTED_UPSTREAMS"
fi

# Log redirections (rate-limited)
iptables -t nat -A DEFENDERPI_DNS -m limit --limit 3/min --limit-burst 5 \
  -j LOG --log-prefix "DEFENDERPI_DNSREDIR: " --log-level 4

# Force redirect all other DNS to Pi-hole
for proto in udp tcp; do
    iptables -t nat -A DEFENDERPI_DNS -p $proto --dport 53 -j DNAT --to-destination "$PI_IP":53
done

echo "[+] DefenderPi DNS enforcement chain applied successfully."
