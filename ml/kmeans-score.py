#!/var/lib/defenderpi/venv/bin/python

import joblib
import pandas as pd
import json
import math
from pathlib import Path
from datetime import datetime, timezone
import os
import time
import numpy as np

# ================= CONFIG =================

MODEL_DIR = Path("/var/lib/defenderpi/ml/models")

KMEANS_MODEL  = MODEL_DIR / "kmeans.joblib"
KMEANS_SCALER = MODEL_DIR / "kmeans_scaler.joblib"
KMEANS_PCA    = MODEL_DIR / "kmeans_pca.joblib"
KMEANS_SPEC   = MODEL_DIR / "kmeans_features.json"
KMEANS_META   = MODEL_DIR / "kmeans_meta.json"

RAW_FEATURE_DIR = Path("/var/lib/defenderpi/ml/features/raw")
STATE_FILE = "/var/lib/defenderpi/ml/device_state_kmeans.json"
SIGNAL_DIR = Path("/var/lib/defenderpi/ml/signals")

GATEWAY_IP = "192.168.50.1"

MIN_BASELINE_WINDOWS = 10
WINDOW_SECONDS = 60
STALE_MULTIPLIER = 2

# =========================================

with open(KMEANS_SPEC) as f:
    KMEANS_FEATURE_COLS = json.load(f)["features"]

with open(KMEANS_META) as f:
    META = json.load(f)

LOG_FEATURES = META.get("log_scaled_features", [])
DIST_PROFILE = META["distance_profile"]

GLOBAL_DISTANCE_LIMITS = {
    "p95": DIST_PROFILE["p95"],
    "p98": DIST_PROFILE["p98"],
    "p99": DIST_PROFILE["p99"]
}

EXTREME_MULTIPLIER = 1.5
MIN_DISTANCE_STREAK = 2
MIN_CLUSTER_JUMP_STREAK = 2

# ---------- helpers ----------

def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE) as f:
        return json.load(f)

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

# ---------- init ----------

kmeans = joblib.load(KMEANS_MODEL)
scaler = joblib.load(KMEANS_SCALER)
pca    = joblib.load(KMEANS_PCA)

SIGNAL_DIR.mkdir(parents=True, exist_ok=True)
state = load_state()

now_ts  = int(time.time())
now_iso = datetime.now(timezone.utc).isoformat()

# ---------- process devices ----------

for raw_file in RAW_FEATURE_DIR.glob("*.csv"):

    device = raw_file.stem

    if device == GATEWAY_IP:
        continue

    try:
        df = pd.read_csv(raw_file, on_bad_lines="skip")  # ✅ FIX
    except Exception:
        continue

    if len(df) < MIN_BASELINE_WINDOWS:
        continue

    # ✅ FIX: remove bad rows
    df = df.dropna(subset=["timestamp"])

    if df.empty:
        continue

    df = df.sort_values("timestamp").reset_index(drop=True)

    last = df.iloc[-1]

    # ✅ FIX: safe timestamp handling
    try:
        window_ts = int(last["timestamp"])
    except Exception:
        continue

    if now_ts - window_ts > WINDOW_SECONDS * STALE_MULTIPLIER:
        continue

    if last.get("flows_count", 0) < 3:
        continue

    st = state.setdefault(
        device,
        {
            "state": "LEARNING",
            "windows": 0,
            "last_ts": None,
            "last_cluster": None,
            "last_signal_ts": None,
            "distance_streak": 0,
            "jump_streak": 0,
            "last_logged_ts": None
        },
    )

    if st["last_ts"] != window_ts:
        st["windows"] += 1
        st["last_ts"] = window_ts

    if st["state"] == "LEARNING":
        if st["windows"] < MIN_BASELINE_WINDOWS:
            print(f"[KMEANS][LEARNING] {device} ({st['windows']}/{MIN_BASELINE_WINDOWS})")
            continue
        st["state"] = "ACTIVE"

    # ---------- FEATURE ENGINEERING ----------

    df["bytes_total"] = df["bytes_out"] + df["bytes_in"]

    df["flows_per_sec"] = df["flows_count"] / WINDOW_SECONDS
    df["bytes_per_flow"] = df["bytes_total"] / (df["flows_count"] + 1)
    df["bytes_per_sec"] = df["bytes_total"] / WINDOW_SECONDS

    df["traffic_balance"] = df["bytes_out"] / (df["bytes_total"] + 1)

    df["dst_ip_density"] = df["unique_dst_ips"] / (df["flows_count"] + 1)
    df["dst_port_density"] = df["unique_dst_ports"] / (df["flows_count"] + 1)

    df["flows_per_sec"] = df["flows_per_sec"].clip(
        upper=df["flows_per_sec"].quantile(0.995)
    )

    df["flow_stability"] = df["flows_count"] / (
        df["flows_count"].rolling(5, min_periods=1).mean() + 1
    )

    X_raw = df.tail(1)[KMEANS_FEATURE_COLS].copy()

    X_raw["flow_stability"] *= 1.3
    X_raw["traffic_balance"] *= 1.2

    X_raw = X_raw.replace([np.inf, -np.inf], 0).fillna(0).clip(lower=0)

    for f in LOG_FEATURES:
        if f in X_raw.columns:
            X_raw[f] = np.log1p(X_raw[f])

    # ---------- PIPELINE ----------

    X_scaled = scaler.transform(X_raw)
    X_used   = pca.transform(X_scaled)

    cluster = int(kmeans.predict(X_used)[0])
    center  = kmeans.cluster_centers_[cluster]

    dist = math.dist(X_used[0], center)

    # ---------- logging ----------

    if st.get("last_logged_ts") != window_ts:
        st["last_logged_ts"] = window_ts
        log_file = "/var/lib/defenderpi/ml/eval_kmeans_distances.csv"

        if not os.path.exists(log_file):
            with open(log_file, "w") as f:
                f.write("timestamp,device,cluster,dist\n")

        with open(log_file, "a") as f:
            f.write(f"{window_ts},{device},{cluster},{dist}\n")

    jump = st["last_cluster"] is not None and st["last_cluster"] != cluster
    st["last_cluster"] = cluster

    if jump:
        st["jump_streak"] += 1
    else:
        st["jump_streak"] = 0

    limits = GLOBAL_DISTANCE_LIMITS
    extreme_limit = limits["p99"] * EXTREME_MULTIPLIER

    severity = "NORMAL"
    confidence = 0.0

    if dist >= limits["p95"]:
        st["distance_streak"] += 1
    else:
        st["distance_streak"] = 0

    if st["distance_streak"] >= MIN_DISTANCE_STREAK:

        if dist >= extreme_limit:
            severity = "HIGH"
            confidence = 0.9

        elif dist >= limits["p99"]:
            severity = "MEDIUM"
            confidence = 0.7

        elif st["jump_streak"] >= MIN_CLUSTER_JUMP_STREAK:
            severity = "LOW"
            confidence = 0.3

    print(f"[KMEANS][{severity}] {device} cluster={cluster} dist={dist:.3f} jump={jump}")

    st["last_dist"] = dist
    st["last_severity"] = severity

    if severity in ("NORMAL", "LOW"):
        continue

    if st.get("last_signal_ts") == window_ts:
        continue

    st["last_signal_ts"] = window_ts

    signal = {
        "ts": window_ts,
        "observed_at": now_ts,
        "iso_ts": now_iso,
        "device": device,
        "model": "kmeans",
        "severity": severity,
        "confidence_hint": round(confidence, 2),
        "meta": {
            "cluster": cluster,
            "dist": round(dist, 4),
        },
    }

    with open(SIGNAL_DIR / f"kmeans-{device}-{window_ts}.json", "w") as f:
        json.dump(signal, f)

save_state(state)
