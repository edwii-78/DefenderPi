#!/opt/defenderpi/venv/bin/python

import time
import sys
import subprocess
import re
import threading
import queue

# ===================== FAST JSON =====================
try:
    import orjson as json
    def loads(x): return json.loads(x)
except:
    import json
    def loads(x): return json.loads(x)

# ===================== INOTIFY =====================
from inotify_simple import INotify, flags

# ===================== CONFIG =====================

EVE_FILE = "/var/log/suricata/eve.json"
AP_SUBNET_PREFIX = "192.168.50."
DEDUP_WINDOW = 0.2
DEBUG = False
OUI_FILE = "/usr/share/misc/oui.txt"

ARP_TTL = 60
READ_SIZE = 65536
CLEANUP_INTERVAL = 30
MAX_EVENTS_PER_LOOP = 1000

# 🔥 ONLY CHANGE: bigger buffers
EVENT_QUEUE_SIZE = 50000
ALERT_QUEUE_SIZE = 50000

sys.path.append("/opt/defenderpi/app")
from defenderpi_alert import write_alert

seen = {}
buffer = ""
last_cleanup = 0

event_queue = queue.Queue(maxsize=EVENT_QUEUE_SIZE)
alert_queue = queue.Queue(maxsize=ALERT_QUEUE_SIZE)

# ===================== PRECOMPILED =====================

MAC_REGEX = re.compile(r"lladdr ([0-9a-f:]{17})")

LOW_PRIORITY_SIGNATURES = (
    "android device connectivity",
    "connectivity check",
    "icmp ping",
    "mdns",
    "upnp",
    "policy check",
    "generic protocol command decode",
    "tls sni",
)

LOW_PRIORITY_CATEGORIES = ()

_arp_cache = {}
_oui_db = {}

# ===================== PRELOAD OUI =====================

try:
    with open(OUI_FILE, "r", errors="ignore") as f:
        for line in f:
            if line.strip():
                prefix = line[:6]
                vendor = line.split("\t")[-1].strip()
                _oui_db[prefix] = vendor
except Exception:
    pass

# ===================== HELPERS ====================

def classify_attack(sig_lower, cat_lower):

    if any(k in sig_lower for k in (
        "brute","credential","password","login","authentication"
    )):
        return "BRUTE"

    if any(k in sig_lower for k in (
        "flood","dos","ddos","syn flood"
    )):
        return "DOS"

    if any(k in sig_lower for k in (
        "malware","trojan","botnet","c2","backdoor","webshell","reverse shell"
    )):
        return "MALWARE"

    if any(k in sig_lower for k in (
        "cmd","command","injection","rce","exec","shell"
    )):
        return "EXPLOIT"

    if any(k in sig_lower for k in (
        "lfi","rfi","file inclusion","traversal","/etc/"
    )):
        return "EXPLOIT"

    if any(k in sig_lower for k in (
        "sqli","sql","xss","script","javascript"
    )):
        return "EXPLOIT"

    if any(k in sig_lower for k in (
        "upload","filename"
    )):
        return "EXPLOIT"

    if "dns" in sig_lower:
        return "DATA_EXFIL"

    if any(k in sig_lower for k in (
        "scan","recon","nmap","probe","enumeration","fuzz","dir","gobuster"
    )):
        return "RECON"

    if any(k in sig_lower for k in (
        "lateral","smb","rdp","dcerpc"
    )):
        return "LATERAL_MOVEMENT"

    if "web-application-attack" in cat_lower:
        return "EXPLOIT"

    if "attempted-admin" in cat_lower:
        return "BRUTE"

    if "trojan-activity" in cat_lower:
        return "MALWARE"

    if "attempted-dos" in cat_lower:
        return "DOS"

    if "attempted-recon" in cat_lower:
        return "RECON"

    return "SUSPICIOUS"


def is_low_priority(sig_lower, cat_lower):
    for k in LOW_PRIORITY_SIGNATURES:
        if k in sig_lower:
            return True
    return False


def normalize_severity(sev):
    if sev == 1:
        return "CRITICAL"
    elif sev == 2:
        return "HIGH"
    elif sev == 3:
        return "MEDIUM"
    else:
        return "LOW"

# ===================== CORE =====================

def periodic_cleanup(now):
    global last_cleanup

    if now - last_cleanup < CLEANUP_INTERVAL:
        return

    expire_time = now - (DEDUP_WINDOW * 2)
    remove_keys = [k for k, v in seen.items() if v < expire_time]

    for k in remove_keys:
        del seen[k]

    last_cleanup = now


def process_event(e):

    if e.get("event_type") != "alert":
        return

    alert = e.get("alert")
    if not alert:
        return

    sev = alert.get("severity")
    if sev is None:
        return

    sig = alert.get("signature", "")
    category = alert.get("category", "")

    sig_lower = sig.lower()
    cat_lower = category.lower()

    if any(k in sig_lower for k in LOW_PRIORITY_SIGNATURES):
        return

    src_ip = e.get("src_ip")
    if not src_ip:
        return

    src_port = e.get("src_port")
    dest_ip = e.get("dest_ip")
    dest_port = e.get("dest_port")
    proto = e.get("proto")
    iface = e.get("in_iface")

    dns = e.get("dns", {})
    dns_query = dns.get("rrname")

    attack_type = classify_attack(sig_lower, cat_lower)

    if src_ip.startswith(AP_SUBNET_PREFIX):
        if attack_type in ("RECON", "BRUTE"):
            attack_type = "LATERAL_MOVEMENT"

    alert_severity = normalize_severity(sev)
    direction = "OUTBOUND" if src_ip.startswith(AP_SUBNET_PREFIX) else "INBOUND"
    action = "BLOCKED" if alert.get("action") == "blocked" else "DETECTED"

    now = time.time()
    periodic_cleanup(now)

    key = (src_ip, hash(sig_lower), dest_port)

    if alert_severity != "CRITICAL":
        last_seen = seen.get(key)
        if last_seen and (now - last_seen < DEDUP_WINDOW):
            return

    seen[key] = now

    try:
        alert_queue.put_nowait({
            "source": "suricata",
            "severity": alert_severity,
            "atype": f"SURICATA_{direction}_{attack_type}",
            "ip": src_ip,
            "action": action,
            "direction": direction,
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "proto": proto,
            "interface": iface,
            "mac": None,
            "vendor": None,
            "rule": sig,
            "category": category,
            "attack_type": attack_type,
            "extra": {"dns_query": dns_query} if dns_query else None
        })
    except:
        pass


# ===================== THREADS =====================

def writer_thread():
    while True:
        alert = alert_queue.get()
        try:
            write_alert(**alert)
        except:
            pass


def reader_thread():
    global buffer

    inotify = INotify()
    inotify.add_watch(EVE_FILE, flags.MODIFY)

    with open(EVE_FILE, "r") as f:
        f.seek(0, 2)

        while True:
            for event in inotify.read():
                if flags.MODIFY in flags.from_mask(event.mask):

                    chunk = f.read(READ_SIZE)
                    if not chunk:
                        continue

                    data = buffer + chunk
                    lines = data.split("\n")
                    buffer = lines[-1]

                    for line in lines[:-1]:
                        if line:
                            try:
                                event_queue.put_nowait(line)
                            except:
                                pass


def processor_thread():
    while True:
        line = event_queue.get()
        try:
            event = loads(line)
            process_event(event)
        except:
            pass


# ===================== MAIN =====================

def main():

    threading.Thread(target=reader_thread, daemon=True).start()
    threading.Thread(target=processor_thread, daemon=True).start()
    threading.Thread(target=writer_thread, daemon=True).start()

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
