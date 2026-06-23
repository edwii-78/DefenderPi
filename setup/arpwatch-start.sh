#!/usr/bin/env bash
# DefenderPi arpwatch starter
# Usage: /usr/local/bin/defenderpi-arpwatch-start.sh <iface>

set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <iface>" >&2
  exit 2
fi

IFACE="$1"

DATA_DIR="/var/lib/arpwatch"
LOG_DIR="/var/log/defenderpi"

DB_FILE="$DATA_DIR/arpwatch-${IFACE}.dat"
LOG_FILE="$LOG_DIR/arpwatch-${IFACE}.log"

# Static DefenderPi AP subnet
SUBNET="192.168.50.0/24"

ARPWATCH_BIN="/usr/sbin/arpwatch"

# Ensure directories
mkdir -p "$DATA_DIR" "$LOG_DIR"

touch "$DB_FILE" "$LOG_FILE"
chown root:root "$DB_FILE" "$LOG_FILE"
chmod 644 "$DB_FILE" "$LOG_FILE"

# Validate arpwatch
if [ ! -x "$ARPWATCH_BIN" ]; then
  echo "ERROR: arpwatch not executable at $ARPWATCH_BIN" >&2
  exit 4
fi

# ------------------------------------------------
# Wait for interface (important for AP startup)
# ------------------------------------------------

for i in {1..30}; do
    if ip link show "$IFACE" > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

if ! ip link show "$IFACE" > /dev/null 2>&1; then
    echo "ERROR: interface $IFACE not found" >&2
    exit 5
fi

{
  echo "==== arpwatch START $(date) IFACE=$IFACE SUBNET=$SUBNET ===="
} >>"$LOG_FILE"

# Run arpwatch in foreground so systemd can track it
exec "$ARPWATCH_BIN" \
    -d \
    -a \
    -i "$IFACE" \
    -f "$DB_FILE" \
    -m root@localhost \
    -n "$SUBNET" >>"$LOG_FILE" 2>&1

