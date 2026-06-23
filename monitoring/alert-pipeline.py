#!/usr/bin/env python3
"""
DefenderPi Alert Pipeline (Structured, Professional)

Consumes ONLY:
  /var/lib/defenderpi/alerts/alert_bus.jsonl

Responsibilities:
- Tail alert bus ONCE
- Validate alert schema
- Push FULL structured alerts to Redis Stream
- Maintain alert rate in RedisTimeSeries

ZERO detection logic.
ZERO enrichment logic.
"""

import json
import time
from pathlib import Path
import redis

# ===================== CONFIG =====================

ALERT_BUS = "/var/lib/defenderpi/alerts/alert_bus.jsonl"

REDIS_URL = "redis://127.0.0.1:6379/0"
EVENT_STREAM = "defender:events"
TS_KEY = "defender:stats:alerts_rate"

STREAM_MAXLEN = 50000
STATS_FLUSH_INTERVAL = 5
TAIL_SLEEP = 0.05   # reduced from 0.2 → faster propagation

# =================================================

r = redis.from_url(REDIS_URL, decode_responses=True)

_buffer = ""
_event_counter = 0
_last_flush = time.time()

# ------------------ REDIS ------------------

def ensure_timeseries():
    try:
        r.execute_command("TS.INFO", TS_KEY)
    except Exception:
        try:
            r.execute_command(
                "TS.CREATE",
                TS_KEY,
                "RETENTION", 3600000,
                "LABELS", "type", "alerts"
            )
        except Exception:
            pass

# ------------------ MAIN ------------------

def main():
    global _buffer, _event_counter, _last_flush

    ensure_timeseries()

    path = Path(ALERT_BUS)
    while not path.exists():
        time.sleep(1)

    with path.open("r") as f:
        f.seek(0, 2)

        while True:
            chunk = f.read(4096)

            if not chunk:
                # Flush stats outside hot path
                now = time.time()
                if now - _last_flush >= STATS_FLUSH_INTERVAL:
                    try:
                        r.execute_command("TS.ADD", TS_KEY, "*", _event_counter)
                        _event_counter = 0
                        _last_flush = now
                    except Exception:
                        pass

                time.sleep(TAIL_SLEEP)
                continue

            _buffer += chunk

            while "\n" in _buffer:
                line, _buffer = _buffer.split("\n", 1)
                if not line.strip():
                    continue

                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # --- Schema Guard ---
                if not isinstance(alert, dict):
                    continue
                if "type" not in alert or "severity" not in alert:
                    continue

                # Faster structured copy
                payload = {k: str(v) for k, v in alert.items() if v is not None}

                # Ensure Redis-compatible timestamp
                payload["ts"] = alert.get("time", str(time.time()))

                try:
                    r.xadd(
                        EVENT_STREAM,
                        payload,
                        maxlen=STREAM_MAXLEN,
                        approximate=True
                    )
                    _event_counter += 1
                except Exception:
                    pass

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

