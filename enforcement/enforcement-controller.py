#!/usr/bin/env python3

import json
import time
import subprocess
import os
from pathlib import Path

# ================= CONFIG =================

DECISION_BUS = "/var/lib/defenderpi/alerts/decision_bus.jsonl"

IPSET_BLOCK = "defender_block"
IPSET_RATE  = "defender_rate"

# 🔥 NEW: separate enforcement buses
ENFORCEMENT_BUS_SURICATA = "/var/lib/defenderpi/alerts/enforcement_bus_suricata.jsonl"
ENFORCEMENT_BUS_ML = "/var/lib/defenderpi/alerts/enforcement_bus_ml.jsonl"

PRIORITY = {
    "suricata": 100,
    "ml": 50
}

TAIL_SLEEP = 0.05

# ==========================================

state = {}
buffer = ""

# ==========================================
# ENFORCEMENT BUS WRITERS
# ==========================================

def write_suricata_event(event):
    try:
        os.makedirs(os.path.dirname(ENFORCEMENT_BUS_SURICATA), exist_ok=True)
        with open(ENFORCEMENT_BUS_SURICATA, "a") as f:
            f.write(json.dumps(event) + "\n")
    except:
        pass


def write_ml_event(event):
    try:
        os.makedirs(os.path.dirname(ENFORCEMENT_BUS_ML), exist_ok=True)
        with open(ENFORCEMENT_BUS_ML, "a") as f:
            f.write(json.dumps(event) + "\n")
    except:
        pass


# ==========================================
# FORMATTERS
# ==========================================

def emit_suricata(ip, decision, ttl, source):
    write_suricata_event({
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "engine": "suricata",
        "type": decision,
        "device": ip,
        "scope": "INTERNAL" if ip.startswith("192.168.50.") else "EXTERNAL",
        "reason": f"{decision} via controller",
        "duration_seconds": ttl,
        "strikes": 1
    })


def emit_ml(ip, decision, entry):
    write_ml_event({
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "type": decision,
        "device": ip,
        "stage": decision,
        "confidence": entry.get("confidence"),
        "reason": entry.get("reason")
    })


# ==========================================
# IPSET
# ==========================================

def run(cmd):
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[ERROR][CMD] {cmd} -> {e}")


def ensure_ipsets():
    run(["ipset", "create", IPSET_BLOCK, "hash:ip", "timeout", "0", "-exist"])
    run(["ipset", "create", IPSET_RATE, "hash:ip", "timeout", "0", "-exist"])


def apply_block(ip, ttl):
    run(["ipset", "add", IPSET_BLOCK, ip, "timeout", str(ttl), "-exist"])
    run(["ipset", "del", IPSET_RATE, ip, "-exist"])


def apply_rate(ip, ttl):
    run(["ipset", "add", IPSET_RATE, ip, "timeout", str(ttl), "-exist"])
    run(["ipset", "del", IPSET_BLOCK, ip, "-exist"])


def remove(ip):
    run(["ipset", "del", IPSET_BLOCK, ip, "-exist"])
    run(["ipset", "del", IPSET_RATE, ip, "-exist"])
    print(f"[REMOVE] {ip}")

    entry = state.get(ip)

    if not entry:
        return

    source = entry.get("source")

    if source == "suricata":
        write_suricata_event({
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "engine": "suricata",
            "type": "UNBLOCK",
            "device": ip,
            "reason": "Controller removal"
        })

    elif source == "ml":
        write_ml_event({
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "type": "UNBLOCK",
            "device": ip,
            "stage": "UNBLOCK",
            "confidence": entry.get("confidence"),
            "reason": entry.get("reason")
        })


# ==========================================
# DECISION HANDLER
# ==========================================

def handle_event(evt):
    try:
        ip = evt.get("device")
        decision = evt.get("decision")
        source = evt.get("source")
        ttl = int(evt.get("ttl", 0))
        now = int(time.time())

        if not ip or not decision or source not in PRIORITY:
            return

        incoming = {
            "decision": decision,
            "source": source,
            "priority": PRIORITY[source],
            "expires_at": now + ttl if ttl > 0 else 0,
            "confidence": evt.get("confidence"),
            "reason": evt.get("reason")
        }

        existing = state.get(ip)

        # REMOVE decisions
        if decision in ("LOG", "IGNORE"):
            remove(ip)
            state.pop(ip, None)
            return

        # APPLY if no existing
        if not existing:
            apply(ip, incoming, ttl)
            return

        # EXPIRED existing
        if existing["expires_at"] and now > existing["expires_at"]:
            apply(ip, incoming, ttl)
            return

        # SKIP redundant
        if (
            existing
            and existing["decision"] == decision
            and incoming["expires_at"] <= existing["expires_at"]
        ):
            return

        # PRIORITY LOGIC
        if incoming["priority"] > existing["priority"]:
            apply(ip, incoming, ttl)

        elif incoming["priority"] == existing["priority"]:
            if incoming["expires_at"] > existing["expires_at"]:
                apply(ip, incoming, ttl)

    except Exception as e:
        print(f"[ERROR][HANDLE_EVENT] {e} | evt={evt}")


def apply(ip, entry, ttl):
    try:
        decision = entry["decision"]
        source = entry["source"]

        if decision == "CRITICAL":
            apply_block(ip, ttl)
            event_type = "BLOCK"

        elif decision == "ALERT":
            apply_rate(ip, ttl)
            event_type = "RATE_LIMIT"

        else:
            return

        state[ip] = entry

        print(f"[ENFORCE] {ip} → {decision} (ttl={ttl})")

        # 🔥 emit based on source
        if source == "suricata":
            emit_suricata(ip, event_type, ttl, source)

        elif source == "ml":
            emit_ml(ip, event_type, entry)

    except Exception as e:
        print(f"[ERROR][APPLY] {ip} -> {e}")


# ==========================================
# EXPIRY CLEANUP
# ==========================================

def cleanup():
    try:
        now = int(time.time())

        for ip, entry in list(state.items()):
            exp = entry.get("expires_at")

            if exp and now > exp:
                remove(ip)
                state.pop(ip)

    except Exception as e:
        print(f"[ERROR][CLEANUP] {e}")


# ==========================================
# MAIN LOOP
# ==========================================

def main():

    global buffer

    ensure_ipsets()

    path = Path(DECISION_BUS)

    while not path.exists():
        time.sleep(1)

    with path.open("r") as f:
        f.seek(0, 2)

        while True:
            try:
                chunk = f.read(8192)

                if not chunk:
                    cleanup()
                    time.sleep(TAIL_SLEEP)
                    continue

                buffer += chunk
                lines = buffer.split("\n")
                buffer = lines[-1]

                for line in lines[:-1]:
                    if not line.strip():
                        continue

                    try:
                        evt = json.loads(line)
                        handle_event(evt)
                    except Exception as e:
                        print(f"[ERROR][JSON] {e} | line={line[:200]}")

                cleanup()

            except Exception as e:
                print(f"[ERROR][MAIN_LOOP] {e}")
                time.sleep(0.1)


if __name__ == "__main__":
    main()
