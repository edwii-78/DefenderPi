#!/bin/bash

iface="$1"

LOGFILE="/var/log/defenderpi/arpwatch-${iface}.log"
OUT="/run/defenderpi/alerts/arpwatch.jsonl"

mkdir -p /run/defenderpi/alerts /run/defenderpi/arp_dedup

while [[ ! -f "$LOGFILE" ]]; do
    sleep 1
done

CACHE="/run/defenderpi/arp_dedup"

# 🔥 MAC → IP cache
declare -A MAC_IP_CACHE
cache_ts=0
CACHE_TTL=5

refresh_cache() {
    now=$(date +%s)

    if (( now - cache_ts < CACHE_TTL )); then
        return
    fi

    MAC_IP_CACHE=()

    while read -r line; do
        echo "$line" | grep -E "REACHABLE|STALE|DELAY|PROBE" >/dev/null || continue

        ip=$(echo "$line" | awk '{print $1}')
        mac=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $(i+1)}')

        [[ -n "$mac" ]] && MAC_IP_CACHE["$mac"]="$ip"

    done < <(ip neigh 2>/dev/null)

    cache_ts=$now
}

resolve_ip_from_mac() {
    mac="$1"
    refresh_cache
    echo "${MAC_IP_CACHE[$mac]}"
}

# 🔥 NEW: count how many IPs a MAC owns
count_mac_ips() {
    mac="$1"
    arp -n | awk -v mac="$mac" '$3 == mac {count++} END {print count+0}'
}

tail -Fn0 "$LOGFILE" | while read -r line; do

    echo "$line" | grep -q "Subject: flip flop" || continue

    # read full block
    block="$line"
    for i in {1..8}; do
        read -r next || break
        block+=$'\n'"$next"
        echo "$next" | grep -q "delta:" && break
    done

    ip=$(echo "$block" | grep -oE 'ip address: [0-9.]+' | awk '{print $3}')
    mac1=$(echo "$block" | grep -oE 'ethernet address: [0-9a-f:]+' | head -1 | awk '{print $3}')
    mac2=$(echo "$block" | grep -oE 'old ethernet address: [0-9a-f:]+' | awk '{print $4}')

    [[ -z "$ip" ]] && continue

    # 🔥 CORRECT attacker detection using ARP behavior
    count1=$(count_mac_ips "$mac1")
    count2=$(count_mac_ips "$mac2")

    if (( count1 > count2 )); then
        attacker_mac="$mac1"
    else
        attacker_mac="$mac2"
    fi

    [[ -z "$attacker_mac" ]] && continue

    # 🔥 resolve ALL attacker IPs via ARP table
    attacker_ips=$(arp -n | awk -v mac="$attacker_mac" '$3 == mac {print $1}')

    # fallback: if no mapping, skip
    [[ -z "$attacker_ips" ]] && continue

    for attacker_ip in $attacker_ips; do

        [[ -z "$attacker_ip" ]] && continue

        # 🚫 NEVER block victim IP
        if [[ "$attacker_ip" == "$ip" ]]; then
            continue
        fi
        now=$(date +%s)
        key="$CACHE/$attacker_ip"

        if [[ -f "$key" ]]; then
            last=$(cat "$key")
            if (( now - last < 60 )); then
                continue
            fi
        fi

        echo "$now" > "$key"

        ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

        echo "{\"source\":\"network\",\"severity\":\"CRITICAL\",\"attack_type\":\"ARP_SPOOF\",\"ip\":\"$attacker_ip\",\"attacker_mac\":\"$attacker_mac\",\"victim_ip\":\"$ip\",\"interface\":\"$iface\",\"time\":\"$ts\"}" >> "$OUT"

    done

done
