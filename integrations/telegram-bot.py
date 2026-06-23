#!/opt/defenderpi/venv/bin/python

import os
import json
import asyncio
import time
import subprocess
import ipaddress
import requests
import hashlib

from telegram import Bot
from telegram.error import TelegramError

import asyncio
from functools import partial
def run_blocking(func, *args, **kwargs):
    loop = asyncio.get_running_loop()
    return loop.run_in_executor(None, partial(func, *args, **kwargs))

BOOT_FLAG = "/var/lib/defenderpi/telegram_boot.sent"

# ===================== CONFIG =====================
ALERT_BUS = "/var/lib/defenderpi/alerts/alert_bus.jsonl"
ENFORCEMENT_BUS = "/var/lib/defenderpi/alerts/enforcement_bus.jsonl"
SURICATA_ENFORCEMENT_BUS = "/var/lib/defenderpi/alerts/enforcement_bus_suricata.jsonl"
NET_ENFORCEMENT_BUS = "/var/lib/defenderpi/alerts/enforcement_bus_network.jsonl"

TELEGRAM_DEDUP_WINDOW = 60
ALERT_HISTORY_MAX = 50

IPSET_NAME = "defender_badips"

SURICATA_SERVICE = "defenderpi-suricata"
BRIDGE_SERVICE = "defenderpi-suricata-bridge"
BOT_SERVICE = "defenderpi-telegram-bot"

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSE_CACHE_TTL = 3600

GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
GSB_CACHE_TTL = 3600

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
URLHAUS_CACHE_TTL = 3600

VT_URL = "https://www.virustotal.com/api/v3/files/"
VT_CACHE_TTL = 3600
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_MAX_UPLOAD_SIZE = 10 * 1024 * 1024

HIBP_PW_URL = "https://api.pwnedpasswords.com/range/"

LEAKCHECK_PUBLIC_URL = "https://leakcheck.io/api/public"
LEAKCHECK_CACHE_TTL = 86400

DASHBOARD_SCRIPT = "/usr/local/sbin/defenderpi-dashboard-access.py"
DASHBOARD_TIMEOUT = 20
DASHBOARD_LOCK = "/run/defenderpi-dashboard.lock"
DASHBOARD_TTL = 300

INTENT_FILE = "/var/lib/defenderpi/ml/intent_override.json"
INTENT_MAX_DURATION = 3 * 3600

# ===================== ENV =====================
try:
    BOT_TOKEN = os.environ["BOT_TOKEN"]
    CHAT_ID = int(os.environ["CHAT_ID"])
    ABUSE_API_KEY = os.environ["ABUSEIPDB_API_KEY"]
    GSB_API_KEY = os.environ["GSB_API_KEY"]
except KeyError as e:
    print(f"[!] Missing environment variable: {e}", flush=True)
    raise SystemExit(1)

bot = Bot(token=BOT_TOKEN)
URLHAUS_API_KEY = os.environ.get("URLHAUS_API_KEY")

# ===================== STATE =====================
sent_cache = {}
alert_history = []
abuse_cache = {}
gsb_cache = {}
urlhaus_cache = {}
vt_cache = {}
pending_vt_upload = False
leakcheck_cache = {}

# ===================== UTIL =====================
# ===================== UTIL =====================
async def svc_active(name):
    """
    Check if a systemd service is active.
    IMPORTANT:
    - This function is ASYNC
    - It internally offloads the blocking subprocess.call
    - DO NOT wrap this function with run_blocking anywhere
    """
    rc = await run_blocking(
        subprocess.call,
        ["systemctl", "is-active", "--quiet", name]
    )
    return rc == 0

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

# ===================== INTENT =====================
def load_intent():
    if not os.path.exists(INTENT_FILE):
        return {}
    try:
        with open(INTENT_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_intent(intent):
    os.makedirs(os.path.dirname(INTENT_FILE), exist_ok=True)
    with open(INTENT_FILE, "w") as f:
        json.dump(intent, f, indent=2)

def parse_duration(s):
    try:
        if s.endswith("m"):
            return int(s[:-1]) * 60
        if s.endswith("h"):
            return int(s[:-1]) * 3600
    except Exception:
        return None
    return None

async def safe_send(msg):
    try:
        await run_blocking(
            bot.send_message,
            chat_id=CHAT_ID,
            text=msg
        )
    except TelegramError as e:
        print(f"[!] Telegram error: {e}", flush=True)
    except Exception as e:
        print(f"[!] Unexpected send error: {e}", flush=True)

# ===================== ABUSEIPDB =====================
def abuse_risk(score):
    if score >= 61:
        return "HIGH"
    if score >= 26:
        return "MEDIUM"
    return "LOW"

def abuse_lookup(ip):
    now = time.time()

    if ip in abuse_cache:
        ts, data = abuse_cache[ip]
        if now - ts < ABUSE_CACHE_TTL:
            return data

    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": "",
    }

    try:
        r = requests.get(
            ABUSE_URL,
            headers=headers,
            params=params,
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()["data"]
        abuse_cache[ip] = (now, data)
        return data
    except Exception as e:
        print(f"[!] AbuseIPDB error: {e}", flush=True)
        return None

async def format_abuse(ip):
    # 🔒 Offload blocking HTTP + cache logic
    data = await run_blocking(abuse_lookup, ip)

    if not data:
        return "AbuseIPDB: lookup failed"

    score = data["abuseConfidenceScore"]
    risk = abuse_risk(score)

    return (
        "\n\n🔍 AbuseIPDB Report\n"
        f"Risk Level : {risk}\n"
        f"Confidence : {score}%\n"
        f"Reports : {data['totalReports']}\n"
        f"Last Reported : {data['lastReportedAt'] or 'Never'}\n"
        f"ISP : {data.get('isp', 'N/A')}\n"
        f"Country : {data.get('countryCode', 'N/A')}"
    )

# ===================== GOOGLE SAFE BROWSING =====================
def gsb_lookup(url):
    now = time.time()
    if url in gsb_cache:
        ts, verdict = gsb_cache[url]
        if now - ts < GSB_CACHE_TTL:
            return verdict
    body = {
        "client": {"clientId": "defenderpi", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        r = requests.post(
            f"{GSB_URL}?key={GSB_API_KEY}",
            json=body,
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        verdict = data.get("matches", [])
        gsb_cache[url] = (now, verdict)
        return verdict
    except Exception as e:
        print(f"[!] GSB error: {e}", flush=True)
        return None

async def format_gsb(url):
    verdict = await run_blocking(gsb_lookup, url)
    if verdict is None:
        return "\n\n🔗 GSB: lookup failed"
    if verdict:
        threats = ", ".join(v["threatType"] for v in verdict)
        return f"\n\n🚫 GSB MALICIOUS\nThreats : {threats}"
    return "\n\n✅ GSB SAFE"

def extract_url(text):
    import re
    if not text:
        return None
    m = re.search(r"(https?://[^\s\"'>)]+)", text)
    return m.group(1) if m else None

# ===================== URLHAUS =====================
def urlhaus_lookup(url):
    now = time.time()

    if url in urlhaus_cache:
        ts, data = urlhaus_cache[url]
        if now - ts < URLHAUS_CACHE_TTL:
            return data
    headers = {}
    if URLHAUS_API_KEY:
        headers["Auth-Key"] = URLHAUS_API_KEY
    try:
        r = requests.post(
            URLHAUS_URL,
            headers=headers,
            data={"url": url},
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        urlhaus_cache[url] = (now, data)
        return data
    except Exception as e:
        print(f"[!] URLhaus error: {e}", flush=True)
        return None

def urlhaus_host_lookup(host):
    now = time.time()
    if host in urlhaus_cache:
        ts, data = urlhaus_cache[host]
        if now - ts < URLHAUS_CACHE_TTL:
            return data
    headers = {}
    if URLHAUS_API_KEY:
        headers["Auth-Key"] = URLHAUS_API_KEY
    try:
        r = requests.post(
            URLHAUS_HOST_URL,
            headers=headers,
            data={"host": host},
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        urlhaus_cache[host] = (now, data)
        return data
    except Exception as e:
        print(f"[!] URLhaus host error: {e}", flush=True)
        return None

async def format_urlhaus(url):
    # 1️⃣ Try direct URL lookup (offloaded)
    data = await run_blocking(urlhaus_lookup, url)
    if data and data.get("query_status") == "ok":
        if data.get("url_status") == "online":
            return (
                "\n\n🦠 URLhaus MALICIOUS (URL)\n"
                f"Threat : {data.get('threat','unknown')}\n"
                f"Host   : {data.get('host','unknown')}\n"
                f"Added  : {data.get('date_added','N/A')}"
            )

    # 2️⃣ Fallback to HOST lookup
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname
    except Exception:
        return "\n\n🧪 URLhaus: invalid URL"
    host_data = await run_blocking(urlhaus_host_lookup, host)
    if host_data and host_data.get("query_status") == "ok":
        return (
            "\n\n🦠 URLhaus MALICIOUS (HOST)\n"
            f"Host        : {host}\n"
            f"URLs Seen   : {host}\n"
            f"First Seen  : {host_data.get('firstseen','N/A')}"
        )
    return "\n\n🧪 URLhaus: no data"

# ===================== VIRUSTOTAL =====================
def vt_lookup(sha256):
    now = time.time()
    if sha256 in vt_cache:
        ts, data = vt_cache[sha256]
        if now - ts < VT_CACHE_TTL:
            return data
    headers = {
        "x-apikey": os.environ["VT_API_KEY"]
    }
    try:
        r = requests.get(
            VT_URL + sha256,
            headers=headers,
            timeout=10,
        )
        if r.status_code == 404:
            vt_cache[sha256] = (now, None)
            return None
        r.raise_for_status()
        data = r.json()
        vt_cache[sha256] = (now, data)
        return data
    except Exception as e:
        print(f"[!] VirusTotal error: {e}", flush=True)
        return None
async def format_vt(sha256):
    # ⛔ OFFLOAD BLOCKING NETWORK CALL
    data = await run_blocking(vt_lookup, sha256)
    if not data:
        return "\n\n🧬 VirusTotal: No data (unknown hash)"
    stats = data["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())
    if malicious >= 10:
        risk = "HIGH"
    elif malicious >= 3:
        risk = "MEDIUM"
    elif malicious > 0:
        risk = "LOW"
    else:
        risk = "CLEAN"
    link = f"https://www.virustotal.com/gui/file/{sha256}"
    return (
        "\n\n🧬 VirusTotal Report\n"
        f"Detections : {malicious} / {total}\n"
        f"Risk       : {risk}\n"
        f"Link       : {link}"
    )

# ===================== HAVE I BEEN PAWN HASH PASSWORD =====================
def hibp_password_check(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        r = requests.get(
            HIBP_PW_URL + prefix,
            headers={"User-Agent": "DefenderPi"},
            timeout=10
        )
        r.raise_for_status()
    except Exception as e:
        return None, f"Lookup failed: {e}"

    for line in r.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return int(count), None
    return 0, None

async def format_pwned_password(password):
    count, err = await run_blocking(hibp_password_check, password)
    if err:
        return "❌ HIBP lookup failed"
    if count == 0:
        return (
            "✅ Password NOT found in known breaches\n"
            "Risk        : LOW\n"
            "Recommendation: Still use unique passwords"
        )
    if count < 100:
        risk = "MEDIUM"
    else:
        risk = "HIGH"
    return (
        "🚨 Pwned Password Detected\n"
        f"Appearances : {count}\n"
        f"Risk        : {risk}\n\n"
        "❗ Do NOT reuse this password\n"
        "❗ Change it everywhere immediately"
    )

# ===================== LEAK CHECK =======================
def leakcheck_lookup(query):
    now = time.time()
    if query in leakcheck_cache:
        ts, data = leakcheck_cache[query]
        if now - ts < LEAKCHECK_CACHE_TTL:
            return data
    headers = {
        "User-Agent": "DefenderPi/1.0 (OSINT; contact admin)",
        "Accept": "application/json",
    }
    try:
        r = requests.get(
            LEAKCHECK_PUBLIC_URL,
            headers=headers,
            params={"check": query},
            timeout=15,
        )
        if r.status_code != 200:
            return {
                "success": False,
                "error": f"HTTP {r.status_code}"
            }
        try:
            data = r.json()
        except Exception:
            return {
                "success": False,
                "error": "Non-JSON response (blocked or rate-limited)"
            }
        leakcheck_cache[query] = (now, data)
        return data
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}

async def format_leakcheck(query):
    # ⬅️ OFFLOADED BLOCKING CALL
    data = await run_blocking(leakcheck_lookup, query)
    disclaimer = (
        "\n\nℹ️ Disclaimer:\n"
        "LeakCheck results are third-party OSINT data.\n"
        "They may be incomplete or outdated."
    )
    if isinstance(data, dict):
        if data.get("error") == "Not found":
            return (
                "✅ No known breaches found\n"
                "Risk : LOW\n"
                "Note : This does NOT guarantee safety" +
                disclaimer
            )
    if not data or not data.get("success"):
        reason = data.get("error", "unknown error") if isinstance(data, dict) else "unknown error"
        return (
            "❌ LeakCheck lookup failed\n"
            f"Reason : {reason}" +
            disclaimer
        )
    found = data.get("found", 0)
    if found == 0:
        return (
            "✅ No known breaches found\n"
            "Risk : LOW\n"
            "Note : This does NOT guarantee safety" +
            disclaimer
        )
    sources = data.get("sources", [])
    lines = []
    for s in sources[:10]:
        name = s.get("name", "unknown")
        date = s.get("date", "unknown")
        lines.append(f"- {name} ({date})")
    return (
        "🚨 Email Found in Breaches\n"
        f"Breaches : {found}\n"
        "Risk     : HIGH\n\n"
        "Sources:\n" +
        "\n".join(lines) +
        "\n\n⚠️ Change passwords immediately" +
        disclaimer
    )
 
# ===================== ALERT FORMAT =====================
async def format_alert(alert):
    """
    Professional structured Suricata alert formatter.
    Uses structured fields from pipeline.
    No external API enrichment.
    """

    direction   = alert.get("direction", "UNKNOWN")
    severity    = alert.get("severity", "UNKNOWN")
    attack_type = alert.get("attack_type", "UNKNOWN")
    rule        = alert.get("rule", "Unknown")
    category    = alert.get("category", "Unknown")

    src_ip   = alert.get("src_ip", "unknown")
    src_port = alert.get("src_port", "unknown")
    dest_ip  = alert.get("dest_ip", "unknown")
    dest_port= alert.get("dest_port", "unknown")
    proto    = alert.get("proto", "unknown")

    mac      = alert.get("mac", "UNKNOWN")
    vendor   = alert.get("vendor", "UNKNOWN")
    iface    = alert.get("interface", "unknown")

    action   = alert.get("action", "DETECTED")

    msg = (
        "🚨 DefenderPi Security Alert\n\n"
        f"Severity   : {severity}\n"
        f"Type       : {attack_type}\n"
        f"Direction  : {direction}\n\n"

        "🖥 Device Context\n"
        f"IP         : {alert.get('ip')}\n"
        f"MAC        : {mac}\n"
        f"Vendor     : {vendor}\n\n"

        "🌐 Network Flow\n"
        f"Source     : {src_ip}:{src_port}\n"
        f"Destination: {dest_ip}:{dest_port}\n"
        f"Protocol   : {proto}\n"
        f"Interface  : {iface}\n\n"

        "🔎 Detection\n"
        f"Rule       : {rule}\n"
        f"Category   : {category}\n\n"

        f"Status     : {action}\n"
        f"Time       : {alert.get('time')}"
    )

    return msg

def should_send(alert):
    """
    Deduplicate based on:
    - IP
    - Attack Type
    - Rule
    """

    key = (
        alert.get("ip"),
        alert.get("attack_type"),
        alert.get("rule"),
    )

    now = time.time()
    last = sent_cache.get(key)

    if last and now - last < TELEGRAM_DEDUP_WINDOW:
        return False

    sent_cache[key] = now
    return True

def cleanup_cache():
    now = time.time()
    for k in list(sent_cache.keys()):
        if now - sent_cache[k] > TELEGRAM_DEDUP_WINDOW * 2:
            del sent_cache[k]

# ===================== ENFORCEMENT FORMAT =====================
def format_enforcement(event):
    base = (
        "🛡 DefenderPi Enforcement\n"
        f"Action : {event.get('type')}\n"
        f"Device : {event.get('device')}"
    )
    if event.get("confidence") is not None:
        base += f"\nConfidence : {event['confidence']}"
    if event.get("reason"):
        base += f"\nReason : {event['reason']}"
    if event["type"] == "BLOCK":
        return "⛔ " + base
    if event["type"] == "RATE_LIMIT":
        return "⚠️ " + base
    if event["type"] == "UNBLOCK":
        return "✅ " + base
    if event["type"] == "INTENT_EXPIRED":
        return "⏰ Intent Expired\n" + base
    return base

# ===================== HEALTH HELPERS =====================
def cpu_usage():
    with open("/proc/stat") as f:
        cpu1 = list(map(int, f.readline().split()[1:]))
    time.sleep(0.3)
    with open("/proc/stat") as f:
        cpu2 = list(map(int, f.readline().split()[1:]))
    idle1 = cpu1[3]
    idle2 = cpu2[3]
    total1 = sum(cpu1)
    total2 = sum(cpu2)
    return round(
        100 * (1 - (idle2 - idle1) / (total2 - total1)),
        1,
    )

async def cpu_usage_async():
    return await run_blocking(cpu_usage)

def mem_usage():
    mem = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":")
            mem[k] = int(v.strip().split()[0])
    total = mem["MemTotal"] // 1024
    free = mem["MemAvailable"] // 1024
    used = total - free
    return used, total

async def mem_usage_async():
    return await run_blocking(mem_usage)

def disk_usage():
    out = subprocess.check_output(
        ["df", "-h", "/"],
        text=True,
    ).splitlines()[1]
    parts = out.split()
    return parts[2], parts[1]

async def disk_usage_async():
    return await run_blocking(disk_usage)

def cpu_temp():
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return round(int(f.read().strip()) / 1000, 1)
    except Exception:
        return "N/A"

async def cpu_temp_async():
    return await run_blocking(cpu_temp)

def uptime():
    with open("/proc/uptime") as f:
        seconds = int(float(f.read().split()[0]))
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    return f"{days}d {hours}h {minutes}m"

async def uptime_async():
    return await run_blocking(uptime)

# ===================== ALERT BUS =====================
async def follow_alert_bus():
    last_inode = None
    f = None

    while True:
        try:
            # Only stat is offloaded (safe & cheap)
            st = await run_blocking(os.stat, ALERT_BUS)
            inode = st.st_ino

            # Handle rotation / first open
            if inode != last_inode:
                if f:
                    try:
                        f.close()
                    except Exception:
                        pass

                f = open(ALERT_BUS, "r")
                f.seek(0, os.SEEK_END)
                last_inode = inode

            # readline is FAST and must stay in event loop
            line = f.readline()

            if not line:
                await asyncio.sleep(0.5)
                continue

            yield line

        except FileNotFoundError:
            # Bus not created yet
            await asyncio.sleep(1)

        except Exception as e:
            print(f"[!] Alert bus error: {e}", flush=True)
            await asyncio.sleep(1)


# ===================== ENFORCEMENT BUS =====================
async def follow_enforcement_bus(path):
    last_inode = None
    f = None

    while True:
        try:
            st = await run_blocking(os.stat, path)
            inode = st.st_ino

            if inode != last_inode:
                if f:
                    await run_blocking(f.close)

                f = await run_blocking(open, path, "r")
                await run_blocking(f.seek, 0, 2)
                last_inode = inode

            line = f.readline()

            if not line:
                await asyncio.sleep(1)
                continue

            yield line

        except Exception:
            await asyncio.sleep(1)

# ===================== COMMANDS =====================

async def cmd_status():
    suricata_ok = await svc_active(SURICATA_SERVICE)
    bridge_ok   = await svc_active(BRIDGE_SERVICE)
    msg = (
        "🛡 DefenderPi Status\n\n"
        f"Suricata : {'OK' if suricata_ok else 'DOWN'}\n"
        f"Bridge : {'OK' if bridge_ok else 'DOWN'}\n"
        "Telegram Bot : OK\n"
        f"Last Alert : {alert_history[-1]['time'] if alert_history else 'never'}"
    )
    await safe_send(msg)


async def cmd_health():
    cpu_task    = cpu_usage_async()
    temp_task   = cpu_temp_async()
    mem_task    = mem_usage_async()
    disk_task   = disk_usage_async()
    uptime_task = uptime_async()

    cpu, temp, mem, disk, up = await asyncio.gather(
        cpu_task,
        temp_task,
        mem_task,
        disk_task,
        uptime_task,
    )

    msg = (
        "🧠 DefenderPi Health\n\n"
        f"CPU Usage : {cpu}%\n"
        f"CPU Temp : {temp} °C\n"
        f"RAM Usage : {mem[0]}MB / {mem[1]}MB\n"
        f"Disk Usage : {disk[0]} / {disk[1]}\n"
        f"Uptime : {up}"
    )
    await safe_send(msg)


async def cmd_clients():
    out = await run_blocking(
        subprocess.check_output,
        ["ip", "neigh"],
        text=True,
    )
    clients = [
        f"{l.split()[0]} {l.split()[4]}"
        for l in out.splitlines()
        if "lladdr" in l
    ]
    await safe_send(
        "📡 AP Clients:\n" +
        ("\n".join(clients[:20]) if clients else "None")
    ) 

async def cmd_dashboard():
    # 🔥 PREVENT MULTIPLE INSTANCES (ONLY CHANGE)
    if await run_blocking(os.path.exists, DASHBOARD_LOCK):
        await safe_send(
            "📊 Dashboard already active\n"
            "Use /dashboard_status"
        )
        return

    await safe_send("📊 Starting temporary Grafana access...")
    try:
        proc = await run_blocking(
            subprocess.Popen,
            ["sudo", DASHBOARD_SCRIPT],
            stdout=subprocess.DEVNULL,   # ⬅️ no need to read stdout anymore
            stderr=subprocess.DEVNULL,
            text=True
        )

        json_file = "/run/defenderpi-dashboard.json"

        start = time.time()
        data = None

        # ✅ wait for file instead of stdout parsing
        while time.time() - start < DASHBOARD_TIMEOUT:
            if await run_blocking(os.path.exists, json_file):
                try:
                    data = await run_blocking(
                        lambda: json.load(open(json_file))
                    )
                    break
                except Exception:
                    await asyncio.sleep(0.2)
                    continue

            await asyncio.sleep(0.5)

        if not data:
            await safe_send(
                "⚠️ Dashboard is starting.\n"
                "Use /dashboard_status in a few seconds."
            )
            return

        if "error" in data:
            await safe_send(
                "📊 Dashboard already active\n"
                f"⏱ Retry after ~{data.get('retry_after_seconds', 300)} seconds\n\n"
                "Use /dashboard_status"
            )
            return

        msg = (
            "📊 Grafana Dashboard Access\n\n"
            f"🔗 URL:\n{data['url']}\n\n"
            f"⏱ Valid for: {data['expires_in_seconds']} seconds\n"
            "🔒 Access: Viewer-only\n"
            "🧨 Auto-expires\n\n"
            "⚠️ Do NOT share this link"
        )

        await safe_send(msg)

    except Exception as e:
        print(f"[!] Dashboard error: {e}", flush=True)
        await safe_send("❌ Failed to start dashboard")

async def cmd_dashboard_revoke():
    pid_files = [
        "/run/defenderpi-dashboard-ngrok.pid",
        "/run/defenderpi-dashboard-proxy.pid",
    ]

    for pid_file in pid_files:
        try:
            pid = await run_blocking(
                lambda p=pid_file: int(open(p).read().strip())
            )
            await run_blocking(os.kill, pid, 15)
            await run_blocking(os.remove, pid_file)
        except:
            pass

    # 🔥 hard kill (authoritative)
    await run_blocking(subprocess.call, ["pkill", "-9", "-f", "ngrok"])
    await run_blocking(subprocess.call, ["pkill", "-9", "-f", "defenderpi-grafana-authproxy"])

    # remove state files
    for f in (
        DASHBOARD_LOCK,
        "/run/defenderpi-dashboard.json",
        "/run/defenderpi-dashboard.url",
    ):
        try:
            await run_blocking(os.remove, f)
        except:
            pass

    await safe_send("🛑 Dashboard access revoked immediately")

async def cmd_dashboard_status():
    URL_FILE = "/run/defenderpi-dashboard.url"

    exists = await run_blocking(os.path.exists, DASHBOARD_LOCK)
    if not exists:
        await safe_send("📊 Dashboard is not active")
        return

    try:
        url = None
        if await run_blocking(os.path.exists, URL_FILE):
            url = await run_blocking(lambda: open(URL_FILE).read().strip())

        start_ts = await run_blocking(
            lambda: int(open(DASHBOARD_LOCK).read().strip())
        )
        elapsed = int(time.time()) - start_ts
        remaining = max(0, DASHBOARD_TTL - elapsed)

        msg = (
            "📊 Dashboard Status\n\n"
            f"🟢 Active\n"
            f"⏱ Remaining time: {remaining} seconds\n"
        )

        msg += "\n🧨 Auto-expires"

        await safe_send(msg)

    except Exception:
        await safe_send("⚠️ Dashboard state unknown")

async def cmd_alerts(n=5):
    lines = [
        f"[{a['severity']}] {a['type']} {a['ip']}"
        for a in alert_history[-n:]
    ]
    await safe_send(
        "🧾 Recent Alerts:\n" +
        ("\n".join(lines) if lines else "None")
    )


async def cmd_block(ip):
    if not validate_ip(ip):
        await safe_send("❌ Invalid IP")
        return

    await run_blocking(
        subprocess.call,
        ["ipset", "add", IPSET_NAME, ip, "-exist"]
    )
    await safe_send(f"⛔ Blocked IP {ip}")


async def cmd_unblock(ip):
    if not validate_ip(ip):
        await safe_send("❌ Invalid IP")
        return

    await run_blocking(
        subprocess.call,
        ["ipset", "del", IPSET_NAME, ip],
        stderr=subprocess.DEVNULL,
    )
    await safe_send(f"✅ Unblocked IP {ip}")


async def cmd_abuse(ip):
    if not validate_ip(ip):
        await safe_send("Invalid IP")
        return

    msg = await format_abuse(ip)
    await safe_send(msg.lstrip("\n"))


async def cmd_gsb(url):
    msg = await format_gsb(url)
    await safe_send(f"🔗 URL: {url}" + msg)


async def cmd_urlhaus(url):
    msg = await format_urlhaus(url)
    await safe_send(f"🔗 URL: {url}" + msg)


async def cmd_vt(sha256):
    if len(sha256) != 64:
        await safe_send("Invalid SHA256 hash")
        return

    msg = await format_vt(sha256)
    await safe_send(f"🧬 Hash: {sha256}" + msg)


async def cmd_vt_upload():
    global pending_vt_upload
    pending_vt_upload = True

    await safe_send(
        "⚠️ VirusTotal File Upload\n\n"
        "Uploading a file will send it to VirusTotal.\n"
        "This may expose sensitive data.\n\n"
        "Reply YES and then upload the file to continue.\n"
        "Reply NO to cancel."
    )

async def cmd_pwned_password(password):
    if len(password) < 6:
        await safe_send("Password too short")
        return
    await safe_send("🔍 Checking password against breach database...")
    result = await format_pwned_password(password)
    await safe_send(result)

async def cmd_leak(email):
    if "@" not in email or "." not in email:
        await safe_send("Invalid email address")
        return
    await safe_send("🔍 Checking email breach exposure...")
    result = await format_leakcheck(email)
    await safe_send(result)

# ===================== Intent Handler =====================
async def cmd_intent_allow(ip, duration, reason):
    if not validate_ip(ip):
        await safe_send("❌ Invalid IP")
        return
    seconds = parse_duration(duration)
    if not seconds or seconds <= 0:
        await safe_send("❌ Invalid duration (use 30m, 1h)")
        return
    if seconds > INTENT_MAX_DURATION:
        await safe_send("❌ Duration too long (max 3h)")
        return
    intent = load_intent()
    now = int(time.time())
    intent[ip] = {
        "mode": "ALLOW_ANOMALY",
        "reason": reason[:64],
        "set_by": "telegram",
        "set_at": now,
        "expires_at": now + seconds
    }
    save_intent(intent)
    await safe_send(
        "🟡 Intent override enabled\n\n"
        f"Device : {ip}\n"
        f"Reason : {reason}\n"
        f"Duration : {duration}\n"
        f"Expires at : {now + seconds}"
    )

async def cmd_intent_revoke(ip):
    intent = load_intent()
    if ip not in intent:
        await safe_send("ℹ️ No active intent for this IP")
        return
    intent.pop(ip)
    save_intent(intent)
    await safe_send(f"🟢 Intent revoked for {ip}")

async def cmd_intent_status(ip=None):
    intent = load_intent()
    now = int(time.time())
    if ip:
        entry = intent.get(ip)
        if not entry:
            await safe_send("ℹ️ No active intent")
            return
        remaining = max(0, entry["expires_at"] - now)
        await safe_send(
            "🟡 Intent status\n\n"
            f"IP : {ip}\n"
            f"Reason : {entry.get('reason')}\n"
            f"Remaining : {remaining}s"
        )
        return
    if not intent:
        await safe_send("ℹ️ No active intents")
        return
    lines = []
    for ip, e in intent.items():
        rem = max(0, e["expires_at"] - now)
        lines.append(f"{ip} — {e.get('reason')} — {rem}s")
    await safe_send("🟡 Active intents:\n" + "\n".join(lines))

# ===================== VT FILE UPLOAD HANDLER =====================
async def handle_vt_file_upload(message):
    global pending_vt_upload

    doc = message.document

    if doc.file_size > VT_MAX_UPLOAD_SIZE:
        pending_vt_upload = False
        await safe_send("❌ File too large (max 10 MB)")
        return

    await safe_send("⏳ Processing file...")

    # ✅ Telegram API call MUST stay on event loop
    tg_file = await run_blocking(bot.get_file, doc.file_id)

    local_path = f"/tmp/{doc.file_name}"

    # ---------- download file (BLOCKING → executor) ----------
    await run_blocking(tg_file.download, custom_path=local_path)

    # ---------- compute SHA256 (BLOCKING → executor) ----------
    def compute_sha256(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    sha256 = await run_blocking(compute_sha256, local_path)

    # ---------- VT lookup (BLOCKING → executor) ----------
    vt_data = await run_blocking(vt_lookup, sha256)

    if vt_data:
        pending_vt_upload = False
        try:
            os.remove(local_path)
        except Exception:
            pass

        await safe_send(
            f"🧬 File already known\n"
            f"SHA256: {sha256}"
            + await format_vt(sha256)
        )
        return

    headers = {"x-apikey": os.environ["VT_API_KEY"]}

    # ---------- upload file (BLOCKING → executor) ----------
    def vt_upload(path):
        with open(path, "rb") as f:
            return requests.post(
                VT_UPLOAD_URL,
                headers=headers,
                files={"file": f},
                timeout=30,
            )

    try:
        r = await run_blocking(vt_upload, local_path)
    finally:
        try:
            os.remove(local_path)
        except Exception:
            pass

    pending_vt_upload = False

    if r.status_code in (200, 201):
        await safe_send(
            "📤 File uploaded to VirusTotal\n"
            f"SHA256: {sha256}\n\n"
            "⏳ Analysis in progress.\n"
            f"Check later with:\n/vt {sha256}"
        )
    else:
        await safe_send("❌ VirusTotal upload failed")

# ===================== TELEGRAM POLLER =====================
async def poll_commands():
    offset = None
    global pending_vt_upload
    while True:
        try:
            # ✅ CORRECT: offload blocking Telegram API call
            updates = await run_blocking(
                bot.get_updates,
                offset=offset,
                timeout=30
            )
            for u in updates:
                offset = u.update_id + 1
                if not u.message or u.message.chat_id != CHAT_ID:
                    continue
                txt = (u.message.text or "").strip()
                parts = txt.split()
                if txt.upper() == "NO":
                    pending_vt_upload = False
                    await safe_send("❌ VirusTotal upload cancelled")
                    continue
                if txt.upper() == "YES" and pending_vt_upload:
                    await safe_send("✅ Upload confirmed. Please send the file.")
                    continue
                if u.message.document and pending_vt_upload:
                    await handle_vt_file_upload(u.message)
                    continue
                if txt == "/status":
                    await cmd_status()
                elif txt == "/health":
                    await cmd_health()
                elif txt == "/clients":
                    await cmd_clients()
                elif parts and parts[0] == "/alerts":
                    n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 5
                    await cmd_alerts(n)
                elif parts and parts[0] == "/block" and len(parts) == 2:
                    await cmd_block(parts[1])
                elif parts and parts[0] == "/unblock" and len(parts) == 2:
                    await cmd_unblock(parts[1])
                elif parts and parts[0] == "/abuse" and len(parts) == 2:
                    await cmd_abuse(parts[1])
                elif parts and parts[0] == "/gsb" and len(parts) == 2:
                    await cmd_gsb(parts[1])
                elif parts and parts[0] == "/urlhaus" and len(parts) == 2:
                    await cmd_urlhaus(parts[1])
                elif parts and parts[0] == "/vt" and len(parts) == 2:
                    await cmd_vt(parts[1])
                elif txt == "/vt_upload":
                    await cmd_vt_upload()
                elif parts and parts[0] == "/pwned" and len(parts) == 2:
                    await cmd_pwned_password(parts[1])
                elif parts and parts[0] == "/leak" and len(parts) == 2:
                    await cmd_leak(parts[1])
                elif parts and parts[0] == "/intent":
                    if len(parts) < 2:
                        await safe_send(
                            "🟡 Intent usage:\n\n"
                            "/intent allow <IP> <duration> <reason>\n"
                            "/intent revoke <IP>\n"
                            "/intent status [IP]\n"
                            "/intent list"
                        )
                        continue
                    sub = parts[1]
                    if sub == "allow" and len(parts) >= 5:
                        await cmd_intent_allow(
                            parts[2],
                            parts[3],
                            " ".join(parts[4:])
                        )
                    elif sub == "revoke" and len(parts) == 3:
                        await cmd_intent_revoke(parts[2])
                    elif sub == "status":
                        await cmd_intent_status(parts[2] if len(parts) == 3 else None)
                    elif sub == "list":
                        await cmd_intent_status()
                    else:
                        await safe_send("❌ Invalid intent command")
                elif txt == "/dashboard":
                    await cmd_dashboard()
                elif txt == "/dashboard_status":
                    await cmd_dashboard_status()
                elif txt == "/dashboard_revoke":
                    await cmd_dashboard_revoke()
            await asyncio.sleep(1)
        except Exception as e:
            print(f"[!] Command poll error: {e}", flush=True)
            await asyncio.sleep(2)

# ===================== MAIN =====================
async def alerts_loop():
    async for line in follow_alert_bus():
        alert = json.loads(line)
        alert_history.append(alert)
        if len(alert_history) > ALERT_HISTORY_MAX:
            alert_history.pop(0)

        # 🔥 use separate object (no mutation)
        formatted_alert = alert

        if alert.get("attack_type") == "ARP_SPOOF":
            formatted_alert = {
                "severity": alert.get("severity"),
                "attack_type": "ARP_SPOOF",
                "direction": "INTERNAL",

                "ip": alert.get("ip"),
                "mac": alert.get("attacker_mac"),
                "vendor": "UNKNOWN",

                "src_ip": alert.get("ip"),
                "src_port": "-",
                "dest_ip": alert.get("victim_ip"),
                "dest_port": "-",
                "proto": "ARP",

                "interface": alert.get("interface"),
                "rule": "ARP Spoofing Detection",
                "category": "MITM",

                "time": alert.get("time"),
                "action": "BLOCKED"
            }

                # ---------------- DHCP NORMALIZATION ----------------
        elif alert.get("attack_type") == "ROGUE_DHCP":
            formatted_alert = {
                "severity": alert.get("severity"),
                "attack_type": "ROGUE_DHCP",
                "direction": "INTERNAL",

                "ip": alert.get("ip"),
                "mac": alert.get("mac"),
                "vendor": "UNKNOWN",

                "src_ip": alert.get("ip"),
                "src_port": "67",
                "dest_ip": "broadcast",
                "dest_port": "68",
                "proto": "DHCP",

                "interface": alert.get("interface"),
                "rule": "Rogue DHCP Server Detected",
                "category": "NETWORK_ATTACK",

                "time": alert.get("time"),
                "action": "BLOCKED"
            }


        if formatted_alert.get("severity") in ("HIGH", "CRITICAL") and should_send(formatted_alert):
            await safe_send(await format_alert(formatted_alert))

        cleanup_cache()

async def enforcement_loop():

    async def handle_bus(path):
        async for line in follow_enforcement_bus(path):
            try:
                event = json.loads(line)
            except Exception:
                continue
            await safe_send(format_enforcement(event))

    await asyncio.gather(
        handle_bus(ENFORCEMENT_BUS),
        handle_bus(SURICATA_ENFORCEMENT_BUS),
        handle_bus(NET_ENFORCEMENT_BUS)
    )

async def main():
    if not os.path.exists(BOOT_FLAG):
        await safe_send("✅ DefenderPi Telegram bot online")
        try:
            with open(BOOT_FLAG, "w") as f:
                f.write(str(int(time.time())))
        except Exception:
            pass
    await asyncio.gather(
        alerts_loop(),
        enforcement_loop(),
        poll_commands()
    )

if __name__ == "__main__":
    asyncio.run(main())

