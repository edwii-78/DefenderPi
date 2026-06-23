#!/bin/bash
# DefenderPi - Pi-hole DNS event JSON logger
# Monitors Pi-hole/dnsmasq logs and writes blocked or NXDOMAIN events to JSON

INTERFACE="$1"
LOG_FILE="/var/log/pihole/pihole.log"
JSON_LOG="/var/log/defenderpi-dns-events.jsonl"

# Ensure log file exists
touch "$JSON_LOG"
chmod 640 "$JSON_LOG"

# Use tail to follow dnsmasq log
tail -n0 -F "$LOG_FILE" | while read -r line; do
    # Example patterns we handle:
    # query[A] malicious.example.com from 192.168.50.59
    # cached malicious.example.com is NXDOMAIN
    # reply malicious.example.com is <CNAME>

    if [[ "$line" =~ query\[([A-Z]+)\]\ ([^[:space:]]+)\ from\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
        qtype="${BASH_REMATCH[1]}"
        domain="${BASH_REMATCH[2]}"
        client="${BASH_REMATCH[3]}"
        last_query_domain="$domain"
        last_query_client="$client"
        last_query_type="$qtype"
        last_query_time=$(date +"%Y-%m-%dT%H:%M:%S")
    elif [[ "$line" =~ (cached|reply)\ ([^[:space:]]+)\ is\ (NXDOMAIN|<CNAME>|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
        result="${BASH_REMATCH[3]}"
        domain="${BASH_REMATCH[2]}"
        if [[ "$result" == "NXDOMAIN" || "$result" == "<CNAME>" ]]; then
            # Log blocked/malicious query in JSON format
            printf '{"timestamp":"%s","interface":"%s","client_ip":"%s","domain":"%s","type":"%s","status":"blocked","result":"%s"}\n' \
                "$last_query_time" "$INTERFACE" "$last_query_client" "$domain" "$last_query_type" "$result" >> "$JSON_LOG"
        fi
    fi
done
