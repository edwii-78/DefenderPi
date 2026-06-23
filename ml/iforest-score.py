#!/var/lib/defenderpi/venv/bin/python

import joblib
import pandas as pd
import json
import time
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import numpy as np

# ================= CONFIG =================

MODEL_DIR = Path("/var/lib/defenderpi/ml/models")

IFOREST_MODEL = MODEL_DIR / "iforest.joblib"
IFOREST_SCALER = MODEL_DIR / "iforest_scaler.joblib"
IFOREST_META = MODEL_DIR / "iforest_meta.json"
IFOREST_FEATURES_FILE = MODEL_DIR / "iforest_features.json"

RAW_FEATURE_DIR = Path("/var/lib/defenderpi/ml/features/raw")
STATE_FILE = "/var/lib/defenderpi/ml/device_state_iforest.json"
SIGNAL_DIR = Path("/var/lib/defenderpi/ml/signals")

GATEWAY_IP = "192.168.50.1"

WINDOW = 60
STALE_MULTIPLIER = 2

MIN_STREAK = 2
MAX_STREAK = 10

# ================= LOAD FEATURE CONTRACT =================

FEATURE_SPEC = json.loads(IFOREST_FEATURES_FILE.read_text())
FEATURES = FEATURE_SPEC["features"]

META = json.loads(IFOREST_META.read_text())
LOG_FEATURES = set(META.get("log_scaled_features", []))
SCORE_PROFILE = META.get("score_profile", {})

# ================= HELPERS =================

def classify(score: float, streak: int) -> str:

    p1 = SCORE_PROFILE.get("p1", SCORE_PROFILE.get("p2", 0.0))
    p2 = SCORE_PROFILE.get("p2", 0.0)
    p5 = SCORE_PROFILE.get("p5", 0.0)

    if score >= p5:
        return "NORMAL"

    if score >= p2:
        return "LOW"

    if score < p1:
        return "HIGH"

    if streak >= 2:
        return "HIGH"

    return "MEDIUM"


def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

# ================= INIT =================

model = joblib.load(IFOREST_MODEL)
scaler = joblib.load(IFOREST_SCALER)

if hasattr(scaler, "n_features_in_") and scaler.n_features_in_ != len(FEATURES):
    sys.exit("❌ Feature mismatch — retrain required")

SIGNAL_DIR.mkdir(parents=True, exist_ok=True)
state = load_state()

now_ts = int(time.time())
now_iso = datetime.now(timezone.utc).isoformat()

# ================= PROCESS DEVICES =================

for raw_file in sorted(RAW_FEATURE_DIR.glob("*.csv")):
    device = raw_file.stem

    if device == GATEWAY_IP:
        continue

    try:
        df = pd.read_csv(raw_file)
        if df.empty or len(df) < 2:
            continue
    except Exception:
        continue

    # ✅ ADD THIS BLOCK RIGHT HERE (before sort)
    df = df.dropna(subset=["timestamp"])
    if df.empty:
        continue

    df = df.sort_values(["timestamp"])

    last = df.iloc[-1]

    try:
        window_ts = int(last["timestamp"])
    except Exception:
        continue

    if now_ts - window_ts > WINDOW * STALE_MULTIPLIER:
        continue

    # ✅ relaxed filter (already correct)
    if last.get("flows_count", 0) == 0:
        continue

    prev = state.get(
        device,
        {"ts": None, "severity": "NORMAL", "streak": 0},
    )

    # ================= FEATURE BUILD (FIXED) =================

    try:
        df["bytes_total"] = df["bytes_out"] + df["bytes_in"]

        df["traffic_skew"] = df["bytes_out"] / (df["bytes_in"] + 1)
        df["traffic_skew"] = df["traffic_skew"].clip(0, 20)

        df["dst_spread_ratio"] = df["unique_dst_ips"] / (df["flows_count"] + 1)
        df["port_spread_ratio"] = df["unique_dst_ports"] / (df["flows_count"] + 1)

        df["dns_anomaly_ratio"] = np.log1p(df["dns_entropy_avg"] * df["dns_queries"])

        # rolling
        flow_roll = df["flows_count"].rolling(5, min_periods=1).mean()
        dns_roll = df["dns_queries"].rolling(5, min_periods=1).mean()

        df["flow_burst_ratio"] = df["flows_count"] / (flow_roll + 1)

        df["flow_delta"] = df["flows_count"].diff().fillna(0)
        df["dns_delta"] = df["dns_queries"].diff().fillna(0)

        df["flow_delta"] = df["flow_delta"] / (flow_roll + 1)
        df["dns_delta"] = df["dns_delta"] / (dns_roll + 1)

        last = df.iloc[-1]

        values = [float(last.get(f, 0)) for f in FEATURES]
        X = pd.DataFrame([values], columns=FEATURES)

    except Exception:
        continue

    X = X.clip(lower=0)

    for f in LOG_FEATURES:
        if f in X.columns:
            X[f] = np.log1p(X[f])

    # ================= SCORE =================

    score = float(model.decision_function(scaler.transform(X))[0])

    # ================= LOG =================

    if prev.get("last_logged_ts") != window_ts:

        prev["last_logged_ts"] = window_ts

        log_file = "/var/lib/defenderpi/ml/eval_iforest_scores.csv"
        row = f"{window_ts},{device},{score}\n"

        if not os.path.exists(log_file):
            with open(log_file, "w") as f:
                f.write("timestamp,device,score\n")

        with open(log_file, "a") as f:
            f.write(row)

    # ================= CLASSIFY =================

    severity = classify(score, prev["streak"])

    if severity == "NORMAL":
        streak = 0
    elif severity == prev["severity"]:
        streak = min(prev["streak"] + 1, MAX_STREAK)
    else:
        streak = 1

    print(f"[IFOREST][{severity}] {device} score={score:.4f}")

    if prev.get("ts") == window_ts and severity == prev["severity"]:
        state[device] = {
            "ts": window_ts,
            "severity": severity,
            "streak": streak,
            "last_score": score,
            "last_logged_ts": prev.get("last_logged_ts")
        }
        continue

    if severity in ("MEDIUM", "HIGH") and streak >= MIN_STREAK:

        signal = {
            "ts": window_ts,
            "observed_at": now_ts,
            "iso_ts": now_iso,
            "device": device,
            "model": "iforest",
            "severity": severity,
            "meta": {
                "score": round(score, 6),
                "streak": streak,
            },
        }

        with open(SIGNAL_DIR / f"iforest-{device}-{window_ts}.json", "w") as f:
            json.dump(signal, f)

    state[device] = {
        "ts": window_ts,
        "severity": severity,
        "streak": streak,
        "last_score": score,
        "last_logged_ts": prev.get("last_logged_ts")
    }

save_state(state)
