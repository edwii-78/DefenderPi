#!/usr/bin/env python3

import json
import math
import csv
import ipaddress
import os
import time
from collections import defaultdict
from pathlib import Path
from datetime import datetime, timezone

# ================= CONFIG =================

EVE_FILE = "/var/log/suricata/eve.json"
STATE_FILE = "/var/lib/defenderpi/ml/data/eve.state"
OUT_DIR = Path("/var/lib/defenderpi/ml/features/raw")

WINDOW = 60
MAX_LAG_WINDOWS = 2   # NOW ENFORCED (REBOOT-SAFE)

# SAFETY LIMITS (do NOT affect logic)
MAX_RUNTIME_SEC = 8
MAX_LINES_PER_RUN = 200_000

AP_NET = ipaddress.ip_network("192.168.50.0/24")
GATEWAY_IP = "192.168.50.1"

# =========================================

OUT_DIR.mkdir(parents=True, exist_ok=True)

FIELDNAMES = [
    "timestamp","device","flows_count","unique_dst_ips","unique_dst_ports",
    "tcp_ratio","udp_ratio","dns_queries","dns_entropy_avg",
    "failed_conn_ratio","bytes_out","bytes_in","out_in_ratio",
    "new_dst_ip_rate","port_fanout_velocity","failed_conn_burst","tcp_syn_rate"
]

# ---------------- helpers ----------------

def is_ap_client(ip):
    try:
        ip = ipaddress.ip_address(ip)
        return (
            ip.version == 4
            and ip in AP_NET
            and not ip.is_multicast
            and not ip.is_loopback
            and not ip.is_link_local
        )
    except Exception:
        return False

def entropy(values):
    if not values:
        return 0.0
    freq = defaultdict(int)
    for v in values:
        freq[v] += 1
    total = sum(freq.values())
    return -sum((c / total) * math.log2(c / total) for c in freq.values())

def window_id(ts):
    return int(ts // WINDOW) * WINDOW

def parse_ts(ts):
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None

# ---------------- STATE ----------------

def load_state():
    if not os.path.exists(STATE_FILE):
        return {
            "inode": None,
            "offset": 0,
            "prev_features": {},
            "last_written_window": {},
        }

    with open(STATE_FILE) as f:
        s = json.load(f)

    s.setdefault("inode", None)
    s.setdefault("offset", 0)
    s.setdefault("prev_features", {})
    s.setdefault("last_written_window", {})

    return s

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

# ---------------- load state ----------------

state = load_state()
prev_features = state["prev_features"]
last_written = state["last_written_window"]

try:
    st = os.stat(EVE_FILE)
except FileNotFoundError:
    exit(0)

# detect Suricata restart / log rotation
inode_changed = state["inode"] != st.st_ino

offset = (
    state["offset"]
    if not inode_changed and state["offset"] <= st.st_size
    else 0
)

if inode_changed:
    prev_features.clear()

flows_buf = defaultdict(list)
dns_buf = defaultdict(list)

pos = offset
start_time = time.monotonic()
lines_read = 0

# ---------------- read eve.json incrementally ----------------

with open(EVE_FILE, "r") as f:
    f.seek(offset)

    while True:

        if time.monotonic() - start_time > MAX_RUNTIME_SEC:
            break

        line = f.readline()
        if not line:
            break

        lines_read += 1
        if lines_read > MAX_LINES_PER_RUN:
            break

        pos = f.tell()

        try:
            e = json.loads(line)
        except Exception:
            continue

        etype = e.get("event_type")

        if etype not in ("flow", "dns"):
            continue

        ts = parse_ts(e.get("timestamp"))
        if ts is None:
            continue

        src_ip = e.get("src_ip")

        if not src_ip or src_ip == GATEWAY_IP or not is_ap_client(src_ip):
            continue

        wid = window_id(ts)

        if etype == "flow":
            flows_buf[(src_ip, wid)].append(e)
        else:
            dns_buf[(src_ip, wid)].append(e)

# ALWAYS advance read state
state["inode"] = st.st_ino
state["offset"] = pos

# ---------------- aggregate windows ----------------

all_windows = set(flows_buf.keys()) | set(dns_buf.keys())
written_windows = set()

for (device, wid) in sorted(all_windows):

    if wid <= last_written.get(device, 0):
        continue

    prev_ts = prev_features.get(device, {}).get("timestamp")

    if prev_ts is not None:
        if wid < prev_ts - (MAX_LAG_WINDOWS * WINDOW):
            continue

    key = (device, wid)

    if key in written_windows:
        continue

    written_windows.add(key)

    flows = flows_buf.get((device, wid), [])
    dns_events = []

    for offset in (0, -WINDOW, WINDOW):
        dns_events.extend(
            dns_buf.get((device, wid + offset), [])
        )

    if not flows and not dns_events:
        continue

    dst_ips = set()
    dst_ports = set()
    tcp = udp = syns = fails = 0
    bytes_out = bytes_in = 0

    for r in flows:

        dst = r.get("dest_ip")
        dport = r.get("dest_port")
        proto = (r.get("proto") or "").lower()

        if dst:
            dst_ips.add(dst)

        if dport:
            dst_ports.add(dport)

        flow = r.get("flow", {})

        if proto == "tcp":
            tcp += 1
            if flow.get("state") == "S0":
                syns += 1
                fails += 1

        elif proto == "udp":
            udp += 1

        # additional fail states
        if flow.get("state") in ("REJ", "RSTO", "RSTR"):
            fails += 1

        bytes_out += flow.get("bytes_toserver", 0)
        bytes_in += flow.get("bytes_toclient", 0)

    dns_queries = [
        d.get("dns", {}).get("rrname")
        for d in dns_events
        if d.get("dns", {}).get("type") == "query"
           and d.get("dns", {}).get("rrname")
    ]

    flow_count = len(flows)

    prev = prev_features.get(device, {})
    continuous = prev.get("timestamp") == wid - WINDOW

    # ---------------- FIXED RATIOS ----------------

    if flow_count > 0:
        tcp_ratio = round(tcp / flow_count, 3)
        udp_ratio = round(udp / flow_count, 3)
        failed_ratio = round(fails / flow_count, 3)
    else:
        tcp_ratio = 0.0
        udp_ratio = 0.0
        failed_ratio = 0.0

    # DNS entropy always computed
    dns_entropy = round(entropy(dns_queries), 3)

    # -------------------------------------------------

    row = {
        "timestamp": wid,
        "device": device,
        "flows_count": flow_count,
        "unique_dst_ips": len(dst_ips),
        "unique_dst_ports": len(dst_ports),
        "tcp_ratio": tcp_ratio,
        "udp_ratio": udp_ratio,
        "dns_queries": len(dns_queries),
        "dns_entropy_avg": dns_entropy,
        "failed_conn_ratio": failed_ratio,
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "out_in_ratio": round(bytes_out / (bytes_in + 1), 3),
        "new_dst_ip_rate": (
            max(0, len(dst_ips) - prev.get("unique_dst_ips", 0)) / WINDOW
            if continuous else 0.0
        ),
        "port_fanout_velocity": (
            max(0, len(dst_ports) - prev.get("unique_dst_ports", 0)) / WINDOW
            if continuous else 0.0
        ),
        "failed_conn_burst": fails,
        "tcp_syn_rate": round(syns / WINDOW, 3),
    }

    prev_features[device] = {
        "unique_dst_ips": len(dst_ips),
        "unique_dst_ports": len(dst_ports),
        "timestamp": wid,
    }

    last_written[device] = wid

    outfile = OUT_DIR / f"{device}.csv"
    write_header = not outfile.exists()

    with open(outfile, "a", newline="") as f:

        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)

        if write_header:
            writer.writeheader()

        writer.writerow(row)

state["prev_features"] = prev_features
state["last_written_window"] = last_written

save_state(state)
