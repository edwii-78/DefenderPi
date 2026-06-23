#!/usr/bin/env python3

import json
import time
import subprocess
from pathlib import Path
from collections import defaultdict, deque

ARP_JSON = "/run/defenderpi/alerts/arpwatch.jsonl"
DHCP_LOG = "/var/log/defenderpi-events.jsonl"

ALERT_BUS = "/var/lib/defenderpi/alerts/alert_bus.jsonl"
ENFORCEMENT_BUS = "/var/lib/defenderpi/alerts/enforcement_bus_network.jsonl"

IPSET_ATTACKERS = "defender_network_quarantine"

BLOCK_TIME = 300

FLIP_WINDOW = 5
FLIP_THRESHOLD = 5

ARP_ALERT_COOLDOWN = 60

last_arp_alert = {}
flip_history = defaultdict(lambda: deque(maxlen=10))

# cache MAC→IP for speed
mac_ip_cache = {}
cache_timestamp = 0
CACHE_TTL = 5

# ------------------------------------------------

def ipset_add(ip, timeout):

    cmd = f"add {IPSET_ATTACKERS} {ip} timeout {timeout}\n"

    subprocess.run(
        ["ipset","restore"],
        input=cmd.encode(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def ip_blocked(ip):

    r = subprocess.run(
        ["ipset","test",IPSET_ATTACKERS,ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return r.returncode == 0

def extend_block(ip):
    ipset_add(ip, BLOCK_TIME)

# ------------------------------------------------

def write_alert(event):

    with open(ALERT_BUS,"a") as f:
        json.dump(event,f)
        f.write("\n")

def write_enforcement(event):

    with open(ENFORCEMENT_BUS,"a") as f:
        json.dump(event,f)
        f.write("\n")

# ------------------------------------------------

def block_ip(ip, reason):

    if not ip:
        return

    if ip_blocked(ip):
        extend_block(ip)
        return

    ipset_add(ip,BLOCK_TIME)

    write_enforcement({
        "time":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
        "engine":"network",
        "type":"BLOCK",
        "device":ip,
        "reason":reason,
        "duration_seconds":BLOCK_TIME
    })

# ------------------------------------------------
# FAST MAC → IP resolver with caching
# ------------------------------------------------

def resolve_ip_from_mac(mac):

    global cache_timestamp

    now=time.time()

    if now-cache_timestamp > CACHE_TTL:

        mac_ip_cache.clear()

        try:
            out=subprocess.check_output(["ip","neigh"]).decode()

            for line in out.splitlines():

                parts=line.split()

                if "lladdr" in parts:

                    # only keep valid neighbour states
                    if not any(state in line for state in ["REACHABLE","STALE","DELAY","PROBE"]):
                        continue

                    ip=parts[0]
                    mac_addr=parts[parts.index("lladdr")+1]

                    mac_ip_cache[mac_addr.lower()] = ip

        except:
            pass

        cache_timestamp=now

    return mac_ip_cache.get(mac.lower())

# ------------------------------------------------

def process_dhcp(event):

    if event.get("category")!="rogue_dhcp":
        return

    ip=event.get("server_ip")

    if not ip:
        return

    alert={
        "source":"network",
        "severity":"CRITICAL",
        "attack_type":"ROGUE_DHCP",
        "ip":ip,
        "mac":event.get("server_mac"),
        "interface":"wlan1",
        "time":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
    }

    write_alert(alert)

    block_ip(ip,"Rogue DHCP server")

# ------------------------------------------------

def process_arp(event):

    if event.get("attack_type") != "ARP_SPOOF":
        return

    attacker_ip = event.get("ip")
    attacker_mac = event.get("attacker_mac")
    victim_ip = event.get("victim_ip")

    if not attacker_ip:
        return

    alert = {
        "source": "network",
        "severity": "CRITICAL",
        "attack_type": "ARP_SPOOF",
        "ip": attacker_ip,
        "attacker_mac": attacker_mac,
        "victim_ip": victim_ip,
        "interface": "wlan1",
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    write_alert(alert)

    block_ip(attacker_ip, "ARP spoofing detected")

# ------------------------------------------------

def follow_dhcp():

    path=Path(DHCP_LOG)

    while not path.exists():
        time.sleep(1)

    with path.open() as f:

        f.seek(0,2)

        while True:

            line=f.readline()

            if not line:
                time.sleep(0.1)
                continue

            try:
                event=json.loads(line)
            except:
                continue

            process_dhcp(event)

# ------------------------------------------------

def follow_arp_json():

    path = Path(ARP_JSON)

    while not path.exists():
        time.sleep(1)

    with path.open() as f:

        f.seek(0, 2)

        while True:

            line = f.readline()

            if not line:
                time.sleep(0.1)
                continue

            try:
                event = json.loads(line)
            except:
                continue

            process_arp(event)

# ------------------------------------------------

def main():

    import threading

    threading.Thread(target=follow_dhcp,daemon=True).start()
    threading.Thread(target=follow_arp_json,daemon=True).start()

    while True:
        time.sleep(5)

if __name__=="__main__":
    main()

