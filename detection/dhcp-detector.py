#!/usr/bin/env python3
"""
DefenderPi DHCP Detector
ROLE: Real-time rogue DHCP detection & alerting (Scapy-based)

This component is AUTHORITATIVE.
Do NOT replace with shell parsing.
"""

from __future__ import annotations

import os
import sys
import time
import json
import signal
import subprocess
import random
from collections import deque, defaultdict
from typing import Optional

from scapy.all import sniff, conf, BOOTP, DHCP, Ether, IP

# ================= CONFIG =================

IFACE = "wlan1"

LOG_GLOBAL = "/var/log/defenderpi-events.jsonl"
LOG_PER_IFACE = "/var/log/dhcp-wlan1.json"
RUN_DIR = "/run/defenderpi"

TRUSTED_FILE = "/etc/defenderpi/trusted_dhcp_servers"

DEDUP_TTL = 300

OFFERS_WINDOW_SEC = 10
OFFERS_THRESHOLD = 2

VOLUME_WINDOW_SEC = 60
VOLUME_THRESHOLD = 120

INLINE_TRIM_LINES = 50000

STARTUP_DELAY = 2
RETRY_SLEEP = 2

BPF_FILTER = "udp and (port 67 or port 68)"

DHCP_MSG_MAP = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}

# ================= HELPERS =================

def now_ts() -> int:
    return int(time.time())

def ensure_dirs():
    os.makedirs(os.path.dirname(LOG_GLOBAL), exist_ok=True)
    os.makedirs(RUN_DIR, exist_ok=True)

def read_trusted() -> set[str]:
    try:
        return {
            ln.strip()
            for ln in open(TRUSTED_FILE)
            if ln.strip() and not ln.startswith("#")
        }
    except FileNotFoundError:
        return set()

# ---------------- Logging (optimized) ----------------

LOG_FD = None
LOG_IFACE_FD = None

def write_jsonl(fd, obj: dict):
    fd.write(json.dumps(obj, separators=(",", ":")) + "\n")
    fd.flush()

def trim_file(path: str, keep: int = INLINE_TRIM_LINES):
    if not os.path.exists(path):
        return
    try:
        with open(path, "rb") as f:
            lines = sum(1 for _ in f)
    except Exception:
        return
    if lines <= keep:
        return
    tmp = path + ".tmp"
    os.system(f"tail -n {keep} '{path}' > '{tmp}' && mv '{tmp}' '{path}'")

# ---------------- In-memory dedupe ----------------

dedupe_cache = {}

def dedupe(key: str) -> bool:
    now = now_ts()

    if key in dedupe_cache:
        if now - dedupe_cache[key] < DEDUP_TTL:
            return False

    dedupe_cache[key] = now
    return True

# ================= STATE =================

class VolumeWindow:
    def __init__(self, window: int):
        self.window = window
        self.ts = deque()

    def add(self, t: int):
        self.ts.append(t)
        cutoff = t - self.window
        while self.ts and self.ts[0] < cutoff:
            self.ts.popleft()

    def count(self) -> int:
        return len(self.ts)

offers_seen: dict[int, set[str]] = defaultdict(set)
offers_ts: dict[int, int] = {}
volume = VolumeWindow(VOLUME_WINDOW_SEC)

trusted_servers = set()

# ================= CLASSIFIER =================

def classify(
    msg: Optional[str],
    server_ip: Optional[str],
    giaddr: Optional[str],
    xid: Optional[int],
) -> tuple[str, str, list[str]]:

    severity = "info"
    category = "dhcp_event"
    reasons: list[str] = []

    if msg in ("offer", "ack", "nak"):
        if not server_ip or server_ip == "0.0.0.0":
            severity = "critical"
            category = "rogue_dhcp"
            reasons.append("invalid_server_ip")
        elif server_ip not in trusted_servers:
            severity = "critical"
            category = "rogue_dhcp"
            reasons.append("untrusted_dhcp_server")

    if giaddr and giaddr != "0.0.0.0":
        reasons.append("giaddr_present")
        if severity != "critical":
            severity = "warning"
            category = "rogue_dhcp"

    if msg == "offer" and xid and server_ip:
        offers_seen[xid].add(server_ip)
        offers_ts[xid] = now_ts()

        for k in list(offers_ts):
            if now_ts() - offers_ts[k] > OFFERS_WINDOW_SEC:
                offers_seen.pop(k, None)
                offers_ts.pop(k, None)

        if len(offers_seen[xid]) >= OFFERS_THRESHOLD:
            severity = "critical"
            category = "rogue_dhcp"
            reasons.append("multiple_dhcp_offers")

    return severity, category, reasons

# ================= PACKET HANDLER =================

def handle_packet(pkt):
    try:
        if not pkt.haslayer(BOOTP) or not pkt.haslayer(DHCP):
            return

        now = now_ts()

        boot = pkt[BOOTP]
        dhcp = pkt[DHCP]
        eth = pkt.getlayer(Ether)
        ip = pkt.getlayer(IP)

        xid = getattr(boot, "xid", None)
        giaddr = getattr(boot, "giaddr", None)
        src_mac = eth.src if eth else None
        src_ip = ip.src if ip else None

        msg_type = None
        server_ip = None

        for opt in dhcp.options:
            if not isinstance(opt, tuple):
                continue
            k, v = opt
            if k == "message-type":
                msg_type = DHCP_MSG_MAP.get(int(v), str(v))
            elif k in ("server_id", "server-identifier"):
                server_ip = v

        if not server_ip and src_ip:
            server_ip = src_ip

        volume.add(now)
        if volume.count() > VOLUME_THRESHOLD:
            return

        sev, cat, reasons = classify(msg_type, server_ip, giaddr, xid)

        dedupe_key = f"{IFACE}_{msg_type}_{server_ip}_{xid or now}"
        if not dedupe(dedupe_key):
            return

        event = {
            "ts": now,
            "source": "dhcp_detector",
            "iface": IFACE,
            "type": "dhcp",
            "dhcp_msg": msg_type,
            "xid": xid,
            "server_ip": server_ip,
            "server_mac": src_mac,
            "giaddr": giaddr,
            "raw_src_ip": src_ip,
            "severity": sev,
            "category": cat,
            "reasons": reasons,
        }

        write_jsonl(LOG_FD, event)

        if sev in ("warning", "critical"):
            write_jsonl(LOG_IFACE_FD, event)

            # trim occasionally (1% probability)
            if random.random() < 0.01:
                trim_file(LOG_PER_IFACE)

    except Exception as e:
        try:
            with open("/var/log/defenderpi/dhcp-detector-error.log", "a") as f:
                f.write(f"{time.strftime('%F %T')} {repr(e)}\n")
        except Exception:
            pass

# ================= MAIN =================

def iface_up_and_ap(iface: str) -> bool:
    try:
        out = subprocess.check_output(["iw", iface, "info"], text=True)
        return "type AP" in out
    except Exception:
        return False

def main():
    ensure_dirs()

    global trusted_servers
    trusted_servers = read_trusted()

    global LOG_FD, LOG_IFACE_FD
    LOG_FD = open(LOG_GLOBAL, "a")
    LOG_IFACE_FD = open(LOG_PER_IFACE, "a")

    if not iface_up_and_ap(IFACE):
        print(f"[DHCP] {IFACE} not in AP mode. Exiting.")
        sys.exit(0)

    conf.sniff_promisc = True
    conf.verb = 0

    time.sleep(STARTUP_DELAY)

    while True:
        try:
            sniff(
                iface=IFACE,
                filter=BPF_FILTER,
                store=0,
                prn=handle_packet,
            )
        except Exception:
            time.sleep(RETRY_SLEEP)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    main()
