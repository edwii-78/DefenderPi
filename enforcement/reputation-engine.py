#!/usr/bin/env python3

import json
import time
import os
import subprocess
from pathlib import Path
from collections import defaultdict, deque

# =========================================================
# CONFIG
# =========================================================

ENFORCEMENT_BUSES = [
    "/var/lib/defenderpi/alerts/enforcement_bus.jsonl",
    "/var/lib/defenderpi/alerts/enforcement_bus_suricata.jsonl",
    "/var/lib/defenderpi/alerts/enforcement_bus_network.jsonl"
]

STATE_FILE = "/var/lib/defenderpi/reputation/reputation.json"
LOG_FILE = "/var/lib/defenderpi/reputation/reputation.log"

PERMA_IPSET = "defender_suricata_perma"

ENGINE_IPSET = {
    "suricata": "defender_suricata",
    "network": "defender_network_quarantine",
    "ml": "defender_ml_block"
}

WINDOW_SECONDS = 3600

PERMANENT_THRESHOLD = 6

ESCALATION = {
    1: 300,       # 5m
    2: 300,       # 5m
    3: 900,       # 15m
    4: 3600,      # 1h
    5: 21600      # 6h
}

VALID_TYPES = {
    "BLOCK",
    "ALREADY_BLOCKED"
}

EVENT_DEDUP_SECONDS = 10

SAVE_INTERVAL = 60
TAIL_SLEEP = 0.05

WHITELIST = {
    "127.0.0.1",
    "192.168.50.1"
}

# =========================================================
# STATE
# =========================================================

offenders = defaultdict(deque)
permanent_blocked = set()

last_save = 0

# =========================================================
# UTIL
# =========================================================

def log(msg):

    ts = time.strftime("%Y-%m-%d %H:%M:%S")

    line = f"[{ts}] {msg}"

    print(line)

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def run(cmd):

    subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False
    )

# =========================================================
# TIMEOUT LOGIC
# =========================================================

def get_timeout(count):

    return ESCALATION.get(count)

# =========================================================
# IPSET
# =========================================================

def load_permanent_blocked():

    global permanent_blocked

    try:

        result = subprocess.run(
            ["ipset", "list", PERMA_IPSET],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            return

        capture = False

        for line in result.stdout.splitlines():

            if line.startswith("Members:"):
                capture = True
                continue

            if capture:

                ip = line.strip()

                if ip:
                    permanent_blocked.add(ip)

        log(
            f"[PERMANENT CACHE LOADED] "
            f"{len(permanent_blocked)} IPs"
        )

    except Exception as e:

        log(f"[PERMANENT CACHE ERROR] {e}")


def ensure_ipset():

    run([
        "ipset",
        "create",
        PERMA_IPSET,
        "hash:ip",
        "-exist"
    ])

    # RAW TABLE DROP
    result = subprocess.run(
        [
            "iptables",
            "-t",
            "raw",
            "-C",
            "PREROUTING",
            "-m",
            "set",
            "--match-set",
            PERMA_IPSET,
            "src",
            "-j",
            "DROP"
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if result.returncode != 0:

        run([
            "iptables",
            "-t",
            "raw",
            "-I",
            "PREROUTING",
            "-m",
            "set",
            "--match-set",
            PERMA_IPSET,
            "src",
            "-j",
            "DROP"
        ])


def ip_permanently_blocked(ip):

    if ip in permanent_blocked:
        return True

    result = subprocess.run(
        ["ipset", "test", PERMA_IPSET, ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0

def permanent_block(ip, reason, engine):

    if ip in permanent_blocked:
        return

    # remove from temporary sets
    for s in ENGINE_IPSET.values():

        run([
            "ipset",
            "del",
            s,
            ip
        ])

    run([
        "ipset",
        "add",
        PERMA_IPSET,
        ip,
        "-exist"
    ])

    # persist permanent bans across reboot
    run([
        "netfilter-persistent",
        "save"
    ])

    # kill existing flows
    run(["conntrack", "-D", "-s", ip])
    run(["conntrack", "-D", "-d", ip])

    run(["ss", "-K", "src", ip])
    run(["ss", "-K", "dst", ip])

    permanent_blocked.add(ip)

    log(
        f"[PERMANENT BLOCK] {ip} "
        f"engine={engine} "
        f"reason='{reason}'"
    )

def escalate_timeout(ip, timeout, engine):

    target_set = ENGINE_IPSET.get(engine)

    if not target_set:
        return

    # force timeout refresh safely
    run([
        "ipset",
        "del",
        target_set,
        ip
    ])

    run([
        "ipset",
        "add",
        target_set,
        ip,
        "timeout",
        str(timeout)
    ])

    log(
        f"[ESCALATE] {ip} "
        f"engine={engine} "
        f"timeout={timeout}s"
    )

# =========================================================
# PERSISTENCE
# =========================================================

def load_state():

    global offenders

    if not os.path.exists(STATE_FILE):
        return

    try:

        with open(STATE_FILE) as f:
            raw = json.load(f)

        now = time.time()

        for ip, timestamps in raw.items():

            dq = deque()

            for ts in timestamps:

                if now - ts <= WINDOW_SECONDS:
                    dq.append(ts)

            if dq:
                offenders[ip] = dq

        log(f"[STATE LOADED] {len(offenders)} tracked IPs")

    except Exception as e:

        log(f"[LOAD ERROR] {e}")


def save_state():

    global last_save

    now = time.time()

    if now - last_save < SAVE_INTERVAL:
        return

    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)

    data = {
        ip: list(dq)
        for ip, dq in offenders.items()
        if dq
    }

    try:

        with open(STATE_FILE, "w") as f:
            json.dump(data, f)

        last_save = now

    except Exception as e:

        log(f"[SAVE ERROR] {e}")

# =========================================================
# PROCESSING
# =========================================================

def process_event(event):

    if event.get("type") not in VALID_TYPES:
        return

    ip = event.get("device")

    if not ip:
        return

    if ip in WHITELIST:
        return

    if ip_permanently_blocked(ip):
        permanent_blocked.add(ip)
        return

    engine = event.get("engine")

    if not engine:

        if "stage" in event:
            engine = "ml"
        else:
            engine = "unknown"

    reason = event.get("reason", "unknown")

    now = time.time()

    dq = offenders[ip]

    # remove old timestamps
    while dq and (now - dq[0]) > WINDOW_SECONDS:
        dq.popleft()

    # anti-spam deduplication
    if dq and (now - dq[-1]) < EVENT_DEDUP_SECONDS:
        return

    dq.append(now)

    count = len(dq)

    log(
        f"[TRACK] {ip} "
        f"count_1h={count} "
        f"engine={engine} "
        f"type={event.get('type')}"
    )

    if count >= PERMANENT_THRESHOLD:

        permanent_block(
            ip,
            reason,
            engine
        )

        return

    timeout = get_timeout(count)

    if timeout:

        escalate_timeout(
            ip,
            timeout,
            engine
        )

# =========================================================
# FOLLOW FILE
# =========================================================

def follow_file(path):

    buffer = ""

    while not Path(path).exists():
        time.sleep(1)

    log(f"[FOLLOWING] {path}")

    with open(path, "r") as f:

        f.seek(0, 2)

        while True:

            chunk = f.read(8192)

            if not chunk:
                save_state()
                time.sleep(TAIL_SLEEP)
                continue

            buffer += chunk

            lines = buffer.split("\n")

            buffer = lines[-1]

            for line in lines[:-1]:

                if not line.strip():
                    continue

                try:

                    event = json.loads(line)

                except Exception:
                    continue

                process_event(event)

            save_state()

# =========================================================
# MAIN
# =========================================================

def main():

    ensure_ipset()

    load_permanent_blocked()

    load_state()

    import threading

    for path in ENFORCEMENT_BUSES:

        t = threading.Thread(
            target=follow_file,
            args=(path,),
            daemon=True
        )

        t.start()

    log("[REPUTATION ENGINE STARTED]")

    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()
