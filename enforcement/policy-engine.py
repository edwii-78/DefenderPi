#!/usr/bin/env python3

import json
import time
from pathlib import Path
from datetime import datetime, timezone
import os

# ================= CONFIG =================

STATE_FILE = "/var/lib/defenderpi/ml/policy_state.json"
DECISION_LOG = "/var/lib/defenderpi/ml/decisions.log"
INTENT_FILE = "/var/lib/defenderpi/ml/intent_override.json"

IFOREST_STATE_FILE = "/var/lib/defenderpi/ml/device_state_iforest.json"
KMEANS_STATE_FILE  = "/var/lib/defenderpi/ml/device_state_kmeans.json"

WINDOW_SECONDS = 60
SILENCE_TIMEOUT = WINDOW_SECONDS * 2

COOLDOWNS = {
    "IGNORE": 60,
    "LOG": 300,
    "ALERT": 120,
    "CRITICAL": 30,
}

MIN_HOLD = {
    "CRITICAL": 180,
    "ALERT": 180,
    "LOG": 120,
}

EXIT_THRESHOLDS = {
    "CRITICAL": 0.60,
    "ALERT": 0.45,
    "LOG": 0.25,
}

# =========================================
# MODEL WEIGHTS
# =========================================

IF_WEIGHTS = {
    "NORMAL": 0.0,
    "LOW": 0.15,
    "MEDIUM": 0.55,
    "HIGH": 1.0,
}

KM_WEIGHTS = {
    "NORMAL": 0.0,
    "LOW": 0.25,
    "MEDIUM": 0.55,
    "HIGH": 1.0,
}

# =========================================
# HUMAN REASON MAPPING
# =========================================

REASON_MAP = {
    "iforest:LOW":
        "Minor deviation from learned behavioral baseline (Isolation Forest)",
    "iforest:MEDIUM":
        "Moderate behavioral deviation detected (Isolation Forest)",
    "iforest:HIGH":
        "Strong behavioral anomaly detected (Isolation Forest)",

    "kmeans:LOW":
        "Minor deviation from expected traffic cluster (KMeans)",
    "kmeans:MEDIUM":
        "Traffic pattern outside normal cluster boundary",
    "kmeans:HIGH":
        "Extreme deviation from expected behavioral cluster",

    "intent:ALLOW_ANOMALY":
        "Anomaly temporarily allowed by administrator override",
}

def humanize_reasons(reason_tokens):
    readable = []
    for r in reason_tokens:
        readable.append(REASON_MAP.get(r, r))
    return sorted(set(readable))

# =========================================
# helpers
# =========================================

def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))

def is_stale(ts, now, limit=180):
    return not ts or (now - ts > limit)

def intent_active(device, intent, now):
    entry = intent.get(device)
    return (
        isinstance(entry, dict)
        and entry.get("mode") == "ALLOW_ANOMALY"
        and now < int(entry.get("expires_at", 0))
    )

# =========================================
# init
# =========================================

state = load_json(STATE_FILE, {})
intent = load_json(INTENT_FILE, {})

if_state = load_json(IFOREST_STATE_FILE, {})
km_state = load_json(KMEANS_STATE_FILE, {})

now_ts = int(time.time())
now_iso = datetime.now(timezone.utc).isoformat()

# =========================================
# evaluation (STATE ONLY)
# =========================================

all_devices = set(state.keys()) | set(if_state.keys()) | set(km_state.keys())

for device in all_devices:

    if_dev = if_state.get(device, {})
    km_dev = km_state.get(device, {})

    if_ts = if_dev.get("ts")
    km_ts = km_dev.get("last_ts")

    if_stale = is_stale(if_ts, now_ts)
    km_stale = is_stale(km_ts, now_ts)

    iforest_sev = "NORMAL" if if_stale else if_dev.get("severity", "NORMAL")
    km_sev = "NORMAL" if km_stale else km_dev.get("last_severity", "NORMAL")

    if_weight = IF_WEIGHTS.get(iforest_sev, 0.0)

    km_conf = km_dev.get("confidence_hint", 1.0)
    km_weight = KM_WEIGHTS.get(km_sev, 0.0) * km_conf

    # 🔥 FIX 2 — ignore stale reasons
    reason_tokens = []
    if not if_stale:
        reason_tokens.append(f"iforest:{iforest_sev}")
    if not km_stale:
        reason_tokens.append(f"kmeans:{km_sev}")

    # ================= DECISION (KMEANS PRIMARY, IF FALLBACK) =================

    # 🔴 1. KMeans HIGH → absolute authority
    if km_sev == "HIGH":
        decision = "CRITICAL"
        confidence = clamp(km_weight + if_weight * 0.3)

    # 🔴 2. KMeans MEDIUM → combine with IF
    elif km_sev == "MEDIUM":

        if iforest_sev in ("MEDIUM", "HIGH"):
            decision = "CRITICAL"
            confidence = clamp(km_weight + if_weight * 0.7)
        else:
            decision = "ALERT"
            confidence = km_weight

    # 🟡 3. KMeans LOW → weak signal, explicitly capped to ALERT max
    elif km_sev == "LOW":

        # 🔥 HARD SAFETY: never allow CRITICAL from LOW
        if iforest_sev == "HIGH":
            decision = "ALERT"
            confidence = clamp(if_weight + km_weight * 0.5)

        elif iforest_sev == "MEDIUM":
            decision = "LOG"
            confidence = clamp(if_weight + km_weight * 0.3)

        else:
            decision = "IGNORE"
            confidence = km_weight

    # 🔵 4. NO KMeans → Isolation Forest fallback
    else:

        if iforest_sev == "HIGH":
            decision = "CRITICAL"
            confidence = if_weight

        elif iforest_sev == "MEDIUM":
            decision = "ALERT"
            confidence = if_weight

        else:
            decision = "IGNORE"
            confidence = 0.0

    if intent_active(device, intent, now_ts):
        decision = "LOG"
        reason_tokens.append("intent:ALLOW_ANOMALY")

    last = state.get(device)
    cooldown = COOLDOWNS.get(decision, 120)

    if last and last["decision"] == decision:
        if now_ts - last["ts"] < cooldown:
            continue

    human_reasons = humanize_reasons(reason_tokens)

    with open(DECISION_LOG, "a") as f:
        f.write(
            f"{now_iso},{device},{decision},"
            f"confidence={confidence:.2f},"
            f"reasons={' | '.join(human_reasons)}\n"
        )

    print(f"[POLICY][{decision}] {device} conf={confidence:.2f}")

    state[device] = {
        "decision": decision,
        "confidence": confidence,
        "reasons": human_reasons,
        "ts": now_ts,
    }

# =========================================
# TRUE HYSTERESIS DOWNGRADE
# =========================================

for device, s in list(state.items()):

    current = s.get("decision")
    held_for = now_ts - s.get("ts", now_ts)

    if_dev = if_state.get(device, {})
    km_dev = km_state.get(device, {})

    if_ts = if_dev.get("ts")
    km_ts = km_dev.get("last_ts")

    iforest_sev = "NORMAL" if is_stale(if_ts, now_ts) else if_dev.get("severity", "NORMAL")
    km_sev = "NORMAL" if is_stale(km_ts, now_ts) else km_dev.get("last_severity", "NORMAL")

    if_weight = IF_WEIGHTS.get(iforest_sev, 0.0)

    km_conf = km_dev.get("confidence_hint", 1.0)
    km_weight = KM_WEIGHTS.get(km_sev, 0.0) * km_conf

    # 🔥 FIX 1 also applied here
    if if_weight > 0 and km_weight > 0:
        current_conf = clamp(if_weight + km_weight * 0.7)
    else:
        current_conf = max(if_weight, km_weight)

    if held_for < MIN_HOLD.get(current, 0) and current_conf > 0.2:
        continue

    exit_threshold = EXIT_THRESHOLDS.get(current, 0.0)

    if current_conf >= exit_threshold:
        continue

    if current == "CRITICAL":
        new_decision = "ALERT"
    elif current == "ALERT":
        new_decision = "LOG"
    elif current == "LOG":
        new_decision = "IGNORE"
    elif current == "IGNORE":
        state.pop(device)
        continue
    else:
        continue

    print(f"[POLICY][DOWNGRADE] {device} {current} → {new_decision}")

    state[device] = {
        "decision": new_decision,
        "confidence": current_conf,
        "reasons": s.get("reasons", []),
        "ts": now_ts,
    }

save_state(state)
