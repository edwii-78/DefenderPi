#!/usr/bin/env python3

import json
import time
import os
import subprocess
from pathlib import Path
from collections import defaultdict

# ===================== CONFIG =====================

ALERT_BUS = "/var/lib/defenderpi/alerts/alert_bus.jsonl"
ENFORCEMENT_BUS = "/var/lib/defenderpi/alerts/enforcement_bus_suricata.jsonl"

IPSET_ATTACKERS = "defender_suricata"
IPSET_GATEWAY_PROTECT = "defender_gateway_protect"

BLOCK_SECONDS = 300
INTERNAL_BLOCK_SECONDS = 300

HOME_SUBNET_PREFIX = "192.168.50."
GATEWAY_IP = "192.168.50.1"

TAIL_SLEEP = 0.01

WHITELIST = {"192.168.50.1"}
RATE_LIMIT_SECONDS = 1.5

# =================================================

buffer = ""
blocked_state = {}

last_block_time = {}
strike_count = defaultdict(int)

os.makedirs(os.path.dirname(ENFORCEMENT_BUS), exist_ok=True)

# ===================== UTIL =====================

def run(cmd):
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_safe(cmd):
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError:
        pass


def write_enforcement(event):
    with open(ENFORCEMENT_BUS, "a") as f:
        f.write(json.dumps(event) + "\n")

# ===================== FIREWALL SETUP =====================

def ensure_ipsets():

    run([
        "ipset", "create", IPSET_ATTACKERS,
        "hash:ip", "timeout", str(BLOCK_SECONDS),
        "-exist"
    ])

    run([
        "ipset", "create", IPSET_GATEWAY_PROTECT,
        "hash:ip", "timeout", "600",
        "-exist"
    ])

    # 🔥 RAW TABLE HARD DROP
    run_safe([
        "iptables", "-t", "raw", "-C", "PREROUTING",
        "-m", "set", "--match-set", IPSET_ATTACKERS, "src", "-j", "DROP"
    ])
    run_safe([
        "iptables", "-t", "raw", "-I", "PREROUTING",
        "-m", "set", "--match-set", IPSET_ATTACKERS, "src", "-j", "DROP"
    ])

    run_safe([
        "iptables", "-t", "raw", "-C", "OUTPUT",
        "-m", "set", "--match-set", IPSET_ATTACKERS, "dst", "-j", "DROP"
    ])
    run_safe([
        "iptables", "-t", "raw", "-I", "OUTPUT",
        "-m", "set", "--match-set", IPSET_ATTACKERS, "dst", "-j", "DROP"
    ])

    # 🔥 EXTRA SAFETY (filter table)
    run_safe([
        "iptables", "-C", "INPUT",
        "-m", "set", "--match-set", IPSET_ATTACKERS, "src", "-j", "DROP"
    ])
    run_safe([
        "iptables", "-I", "INPUT",
        "-m", "set", "--match-set", IPSET_ATTACKERS, "src", "-j", "DROP"
    ])

    run_safe([
        "iptables", "-C", "FORWARD",
        "-m", "set", "--match-set", IPSET_ATTACKERS, "src", "-j", "DROP"
    ])
    run_safe([
        "iptables", "-I", "FORWARD",
        "-m", "set", "--match-set", IPSET_ATTACKERS, "src", "-j", "DROP"
    ])

# ===================== DECISION =====================
def should_block(alert):

    severity = alert.get("severity")

    if severity == "LOW":
        return False

    return True

# ===================== HARD BLOCK =====================

def kill_conntrack(ip):
    run(["conntrack", "-D", "-s", ip])
    run(["conntrack", "-D", "-d", ip])
    run(["conntrack", "-D", "--orig-src", ip])
    run(["conntrack", "-D", "--reply-src", ip])


def kill_sockets(ip):
    run(["ss", "-K", "src", ip])
    run(["ss", "-K", "dst", ip])

def rate_limited(ip):
    now = time.time()
    last = last_block_time.get(ip, 0)

    if now - last < RATE_LIMIT_SECONDS:
        return True

    last_block_time[ip] = now
    return False


def block_ip(ip, attack_type):

    if ip in WHITELIST:
        return

    if ip in blocked_state:
        return

    if rate_limited(ip):
        return

    is_internal = ip.startswith(HOME_SUBNET_PREFIX)
    timeout = INTERNAL_BLOCK_SECONDS if is_internal else BLOCK_SECONDS

    strike_count[ip] += 1
    if strike_count[ip] >= (2 if is_internal else 3):
        timeout *= 2

    run([
        "ipset", "add", IPSET_ATTACKERS,
        ip,
        "timeout", str(timeout),
        "-exist"
    ])
    
    # 🔥 NEW — HARD DROP IMMEDIATELY (kills retransmit window)
    run_safe([
        "iptables", "-I", "FORWARD", "1",
        "-s", ip,
        "-j", "DROP"
    ])
    kill_conntrack(ip)
    kill_sockets(ip)

    expiry = time.time() + timeout
    blocked_state[ip] = expiry

    write_enforcement({
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "engine": "suricata",
        "type": "BLOCK",
        "device": ip,
        "scope": "INTERNAL" if is_internal else "EXTERNAL",
        "reason": f"{attack_type} detected",
        "duration_seconds": timeout,
        "strikes": strike_count[ip]
    })


def protect_gateway(ip):

    if ip in WHITELIST:
        return

    run([
        "ipset", "add", IPSET_GATEWAY_PROTECT,
        ip,
        "timeout", "600",
        "-exist"
    ])

    kill_conntrack(ip)
    kill_sockets(ip)

# ===================== UNBLOCK =====================

# ===================== UNBLOCK =====================

# 🔥 NEW — verify real ipset state
def ip_still_blocked(ip):
    result = subprocess.run(
        ["ipset", "test", IPSET_ATTACKERS, ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


# 🔥 ADD THIS FUNCTION HERE (EXACT LOCATION)
def remove_forward_drop(ip):
    while True:
        result = subprocess.run(
            ["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if result.returncode != 0:
            break

def check_unblocks():

    now = time.time()

    for ip, expiry in list(blocked_state.items()):
        if now >= expiry and not ip_still_blocked(ip):
            remove_forward_drop(ip)
            del blocked_state[ip]
            strike_count.pop(ip, None)

            write_enforcement({
                "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "engine": "suricata",
                "type": "UNBLOCK",
                "device": ip,
                "reason": "Quarantine period expired"
            })

# ===================== PROCESS =====================

def process_alert(alert):

    if alert.get("source") != "suricata":
        return

    ip = alert.get("ip")
    if not ip:
        return

    if ip in WHITELIST:
        return

    if not should_block(alert):
        return

    attack_type = alert.get("attack_type", "UNKNOWN")

    block_ip(ip, attack_type)

    if alert.get("dest_ip") == GATEWAY_IP:
        protect_gateway(ip)

# ===================== MAIN =====================

def main():
    global buffer

    ensure_ipsets()

    path = Path(ALERT_BUS)

    while not path.exists():
        time.sleep(1)

    with path.open("r") as f:
        f.seek(0, 2)

        while True:
            chunk = f.read(8192)

            if not chunk:
                check_unblocks()
                time.sleep(TAIL_SLEEP)
                continue

            buffer += chunk
            lines = buffer.split("\n")
            buffer = lines[-1]

            for line in lines[:-1]:
                if not line.strip():
                    continue

                try:
                    alert = json.loads(line)
                except Exception:
                    continue

                process_alert(alert)

            check_unblocks()


if __name__ == "__main__":
    main()
