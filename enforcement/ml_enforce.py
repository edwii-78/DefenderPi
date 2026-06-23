#!/usr/bin/env python3

import json
import subprocess
import os
from datetime import datetime, timezone

# ================= CONFIG =================

POLICY_FILE     = "/var/lib/defenderpi/ml/policy_state.json"
ENFORCE_STATE   = "/var/lib/defenderpi/ml/enforce_state.json"
ENFORCE_LOG     = "/var/lib/defenderpi/ml/enforcement.log"
INTENT_FILE     = "/var/lib/defenderpi/ml/intent_override.json"

ENFORCEMENT_BUS = "/var/lib/defenderpi/alerts/enforcement_bus.jsonl"

IPSET_BLOCK = "defender_ml_block"
IPSET_RATE  = "defender_ml_rate_limit"

BLOCK_TIMEOUT = 300
RATE_TIMEOUT  = 300

SURICATA_IPSETS = [
    "defender_suricata",
    "defender_suricata_perma",
    "defender_network_quarantine"
]

# =========================================
# ------------ JSON HELPERS ---------------
# =========================================

def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


def log(msg):
    ts = datetime.now(timezone.utc).isoformat()
    with open(ENFORCE_LOG, "a") as f:
        f.write(f"{ts} {msg}\n")
    print(msg)


def emit_event(event_type, device, stage=None, confidence=None, reason=None):
    event = {
        "time":       datetime.now(timezone.utc).isoformat(),
        "type":       event_type,
        "device":     device,
        "stage":      stage,
        "confidence": confidence,
        "reason":     reason,
    }

    os.makedirs(os.path.dirname(ENFORCEMENT_BUS), exist_ok=True)

    with open(ENFORCEMENT_BUS, "a") as f:
        f.write(json.dumps(event) + "\n")


# =========================================
# ------------ IPSET HELPERS --------------
# =========================================

def run(cmd):
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def ipset_add(setname, ip, timeout):
    cmd = f"add {setname} {ip} timeout {timeout}\n"
    subprocess.run(
        ["ipset", "restore"],
        input=cmd.encode(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False
    )


def ipset_del(setname, ip):
    subprocess.run(
        ["ipset", "del", setname, ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False
    )

def kill_conntrack(ip):
    run(["conntrack", "-D", "-s", ip])
    run(["conntrack", "-D", "-d", ip])
    run(["conntrack", "-D", "--orig-src", ip])
    run(["conntrack", "-D", "--reply-src", ip])

def kill_sockets(ip):
    run(["ss", "-K", "src", ip])
    run(["ss", "-K", "dst", ip])

# ✅ FIXED FUNCTION (ONLY CHANGE)
def load_ipset_members(setname):
    try:
        result = subprocess.run(
            ["ipset", "list", setname],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode != 0:
            return set()

        members = set()
        capture = False

        for line in result.stdout.splitlines():
            if line.startswith("Members:"):
                capture = True
                continue
            if capture:
                parts = line.strip().split()
                if parts:
                    members.add(parts[0])  # ✅ extract ONLY IP

        return members

    except Exception:
        return set()


def ensure_ipsets():
    run([
        "ipset", "create", IPSET_BLOCK,
        "hash:ip", "timeout", str(BLOCK_TIMEOUT),
        "-exist"
    ])

    run([
        "ipset", "create", IPSET_RATE,
        "hash:ip", "timeout", str(RATE_TIMEOUT),
        "-exist"
    ])


# =========================================
# ---------------- INIT -------------------
# =========================================

ensure_ipsets()

policy = load_json(POLICY_FILE, {})
state  = load_json(ENFORCE_STATE, {})
intent = load_json(INTENT_FILE, {})

now_ts = int(datetime.now(timezone.utc).timestamp())

state_changed = False
intent_changed = False


# =========================================
# EXPIRE CHECK
# =========================================

for device, s in list(state.items()):

    stage = s.get("stage")
    last_ts = s.get("last_ts", 0)

    if stage == "BLOCK":
        timeout = BLOCK_TIMEOUT
    elif stage == "RATE_LIMIT":
        timeout = RATE_TIMEOUT
    else:
        continue

    if now_ts - last_ts >= timeout:

        log(f"[UNBLOCK-EXPIRED] {device}")

        emit_event(
            "UNBLOCK",
            device,
            "UNBLOCK",
            s.get("confidence"),
            "Quarantine period expired"
        )

        if stage == "BLOCK":
            ipset_del(IPSET_BLOCK, device)
        if stage == "RATE_LIMIT":
            ipset_del(IPSET_RATE, device)

        state.pop(device)
        state_changed = True


# =========================================
# INTENT EXPIRY
# =========================================

for device, entry in list(intent.items()):

    if entry.get("mode") == "ALLOW_ANOMALY":

        if int(entry.get("expires_at", 0)) <= now_ts:

            log(f"[INTENT-EXPIRED] {device}")

            emit_event("INTENT_EXPIRED", device, reason=entry.get("reason"))

            intent.pop(device)
            intent_changed = True

            ipset_del(IPSET_BLOCK, device)
            ipset_del(IPSET_RATE, device)

            state.pop(device, None)
            state_changed = True


# =========================================
# CLEANUP
# =========================================

for device in list(state.keys()):

    blocked = False
    for s in SURICATA_IPSETS:
        if device in load_ipset_members(s):
            blocked = True
            break

    if not blocked and state.get(device, {}).get("stage") == "EXTERNAL_BLOCK":
        log(f"[EXTERNAL-UNBLOCK] {device}")
        state.pop(device)
        state_changed = True
        continue

    if device not in policy and device not in intent:

        log(f"[CLEANUP] stale device {device}")

        current_stage = state.get(device, {}).get("stage")

        if current_stage == "BLOCK":
            ipset_del(IPSET_BLOCK, device)
        if current_stage == "RATE_LIMIT":
            ipset_del(IPSET_RATE, device)

        state.pop(device)
        state_changed = True


# =========================================
# ENFORCEMENT
# =========================================

ipset_cache = {
    s: load_ipset_members(s)
    for s in SURICATA_IPSETS
}

for device, p in policy.items():

    intent_entry = intent.get(device)
    if intent_entry and intent_entry.get("mode") == "ALLOW_ANOMALY":
        continue

    blocked = False
    source_set = None

    for s, members in ipset_cache.items():
        if device in members:
            blocked = True
            source_set = s
            break

    if blocked:
        prev = state.get(device)

        if prev and prev.get("stage") == "EXTERNAL_BLOCK":
            continue

        log(f"[SKIP-ALREADY-BLOCKED] {device} in {source_set}")

        emit_event(
            "ALREADY_BLOCKED",
            device,
            "EXTERNAL_BLOCK",
            p.get("confidence"),
            f"Suppressed ML enforcement (handled by {source_set})"
        )

        state[device] = {
            "stage": "EXTERNAL_BLOCK",
            "confidence": p.get("confidence"),
            "last_ts": now_ts
        }
        state_changed = True

        continue

    decision = p.get("decision", "IGNORE")
    confidence = float(p.get("confidence", 0.0))
    reasons_list = p.get("reasons", [])
    reason_text = " | ".join(reasons_list) if reasons_list else None

    current_stage = state.get(device, {}).get("stage")

    if decision == "CRITICAL":

        if current_stage != "BLOCK":

            log(f"[BLOCK] {device}")

            emit_event("BLOCK", device, "BLOCK", confidence, reason_text)

            ipset_add(IPSET_BLOCK, device, BLOCK_TIMEOUT)
            
            if current_stage == "RATE_LIMIT":
                ipset_del(IPSET_RATE, device)
            # 🔥 CRITICAL FIX — kill existing connections (AFTER FINAL STATE)
            kill_conntrack(device)
            kill_sockets(device)
            state[device] = {
                "stage": "BLOCK",
                "confidence": confidence,
                "last_ts": now_ts
            }
            state_changed = True

        else:
            state[device]["last_ts"] = now_ts

        continue

    if decision == "ALERT":

        if current_stage != "RATE_LIMIT":

            log(f"[RATE_LIMIT] {device}")

            emit_event("RATE_LIMIT", device, "RATE_LIMIT", confidence, reason_text)

            ipset_add(IPSET_RATE, device, RATE_TIMEOUT)

            if current_stage == "BLOCK":
                ipset_del(IPSET_BLOCK, device)

            state[device] = {
                "stage": "RATE_LIMIT",
                "confidence": confidence,
                "last_ts": now_ts
            }
            state_changed = True

        else:
            state[device]["last_ts"] = now_ts

        continue

    if current_stage in {"BLOCK", "RATE_LIMIT"}:

        log(f"[UNBLOCK] {device}")

        emit_event("UNBLOCK", device, "UNBLOCK", confidence, reason_text)

        if current_stage == "BLOCK":
            ipset_del(IPSET_BLOCK, device)
        if current_stage == "RATE_LIMIT":
            ipset_del(IPSET_RATE, device)

    if device in state:
        state.pop(device)
        state_changed = True


# =========================================
# SAVE
# =========================================

if state_changed:
    save_json(ENFORCE_STATE, state)

if intent_changed:
    save_json(INTENT_FILE, intent)
