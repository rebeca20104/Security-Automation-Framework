#!/usr/bin/env python3
"""
Wazuh -> VirusTotal -> Discord + SQLite pipeline.

Run:  python3 wazuh_vt_pipeline.py
Needs: pip install requests
"""
import os
import sys
import time
import sqlite3
import logging
import ipaddress
import requests
import urllib3

WAZUH_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_USER = os.getenv("WAZUH_USER", "admin")
WAZUH_PASS = os.getenv("WAZUH_PASS")
VT_KEY = os.getenv("VT_API_KEY")
DISCORD = os.getenv("DISCORD_WEBHOOK")
THRESHOLD = int(os.getenv("CRITICAL_THRESHOLD", "5"))
POLL = int(os.getenv("POLL_SECONDS", "30"))
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() == "true"
DB_PATH = os.getenv("DB_PATH", "security.db")
CACHE_TTL = 24 * 3600          # re-check an indicator after 24h
NOTIFY_LEVEL = int(os.getenv("NOTIFY_LEVEL", "99"))
VT_MIN_INTERVAL = 15           # free tier: 4 requests/min

if not VERIFY_TLS:
    urllib3.disable_warnings()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("pipeline")
_last_vt_call = 0.0


# ---------- database ----------
def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY, ts TEXT, agent TEXT, rule_id TEXT,
        level INTEGER, description TEXT, file_path TEXT);
    CREATE TABLE IF NOT EXISTS indicators (
        indicator TEXT PRIMARY KEY, type TEXT, malicious INTEGER,
        suspicious INTEGER, verdict TEXT, checked_at REAL);
    CREATE TABLE IF NOT EXISTS alert_indicators (
        alert_id TEXT, indicator TEXT, PRIMARY KEY (alert_id, indicator));
    CREATE TABLE IF NOT EXISTS notifications (
        alert_id TEXT, indicator TEXT, sent_at REAL, status TEXT,
        PRIMARY KEY (alert_id, indicator));
    """)
    db.commit()
    return db


def get_state(db, key, default=None):
    row = db.execute("SELECT v FROM state WHERE k=?", (key,)).fetchone()
    return row[0] if row else default


def set_state(db, key, value):
    db.execute("INSERT OR REPLACE INTO state VALUES (?,?)", (key, value))
    db.commit()


# ---------- Wazuh ----------
def fetch_alerts(since):
    body = {
        "size": 100,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {"range": {"timestamp": {"gte": since}}},
    }
    r = requests.post(
        f"{WAZUH_URL}/wazuh-alerts-*/_search",
        json=body, auth=(WAZUH_USER, WAZUH_PASS),
        verify=VERIFY_TLS, timeout=30,
    )
    r.raise_for_status()
    return [h["_source"] | {"_id": h["_id"]} for h in r.json()["hits"]["hits"]]


def is_public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def extract_indicators(alert):
    """Return list of (indicator, type) found in the alert."""
    found = []
    sc = alert.get("syscheck", {})
    h = sc.get("sha256_after") or sc.get("md5_after")
    if h:
        found.append((h, "file"))

    data = alert.get("data", {})
    candidates = [data.get(k) for k in ("srcip", "dstip", "src_ip", "dst_ip")]
    candidates.append(alert.get("data", {}).get("win", {}).get("eventdata", {}).get("ipAddress"))
    for ip in candidates:
        if ip and is_public_ip(ip):
            found.append((ip, "ip"))
    return list(dict.fromkeys(found))  # dedupe, keep order


# ---------- VirusTotal ----------
def vt_lookup(db, indicator, itype):
    """Return (malicious, suspicious, verdict) using cache + rate limiting."""
    global _last_vt_call
    row = db.execute(
        "SELECT malicious, suspicious, verdict, checked_at FROM indicators WHERE indicator=?",
        (indicator,),
    ).fetchone()
    if row and time.time() - row[3] < CACHE_TTL:
        return row[0], row[1], row[2]

    path = "files" if itype == "file" else "ip_addresses"
    url = f"https://www.virustotal.com/api/v3/{path}/{indicator}"

    for attempt in range(2):
        wait = VT_MIN_INTERVAL - (time.time() - _last_vt_call)
        if wait > 0:
            time.sleep(wait)
        _last_vt_call = time.time()
        r = requests.get(url, headers={"x-apikey": VT_KEY}, timeout=20)
        if r.status_code == 429:
            log.warning("VT rate limited, sleeping 60s")
            time.sleep(60)
            continue
        break
    else:
        return None  # give up for now; will retry on next poll

    if r.status_code == 404:
        mal, sus, verdict = 0, 0, "unknown"
    elif r.ok:
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        verdict = "critical" if mal >= THRESHOLD else ("suspicious" if mal or sus else "clean")
    else:
        log.error("VT error %s for %s", r.status_code, indicator)
        return None

    db.execute(
        "INSERT OR REPLACE INTO indicators VALUES (?,?,?,?,?,?)",
        (indicator, itype, mal, sus, verdict, time.time()),
    )
    db.commit()
    return mal, sus, verdict


# ---------- Discord ----------
def notify_discord(alert, indicator, itype, mal, sus):
    gui = "file" if itype == "file" else "ip-address"
    embed = {
        "title": f"CRITICAL: malicious {itype} detected",
        "color": 0xE74C3C,
        "fields": [
            {"name": "Agent", "value": alert.get("agent", {}).get("name", "n/a"), "inline": True},
            {"name": "Rule", "value": f"{alert['rule']['id']} (level {alert['rule']['level']})", "inline": True},
            {"name": "Description", "value": alert["rule"]["description"][:1000]},
            {"name": "Indicator", "value": f"`{indicator}`"},
            {"name": "VT detections", "value": f"{mal} malicious / {sus} suspicious"},
            {"name": "VirusTotal", "value": f"https://www.virustotal.com/gui/{gui}/{indicator}"},
        ],
        "timestamp": alert["timestamp"].replace("+0000", "+00:00"),
    }
    path = alert.get("syscheck", {}).get("path")
    if path:
        embed["fields"].insert(3, {"name": "File", "value": path[:1000]})

    r = requests.post(DISCORD, json={"embeds": [embed]}, timeout=15)
    if r.status_code == 429:
        time.sleep(float(r.json().get("retry_after", 2)))
        r = requests.post(DISCORD, json={"embeds": [embed]}, timeout=15)
    return r.ok

def notify_alert(alert):
    r = alert["rule"]
    embed = {
        "title": f"Wazuh alert (level {r['level']})",
        "color": 0xF39C12,
        "fields": [
            {"name": "Agent", "value": alert.get("agent", {}).get("name", "n/a"), "inline": True},
            {"name": "Rule", "value": str(r["id"]), "inline": True},
            {"name": "Description", "value": r["description"][:1000]},
        ],
    }
    requests.post(DISCORD, json={"embeds": [embed]}, timeout=15)

# ---------- main loop ----------
def process(db, alert):
    aid = alert["_id"]
    if db.execute("SELECT 1 FROM alerts WHERE id=?", (aid,)).fetchone():
        return  # already handled

    db.execute(
        "INSERT INTO alerts VALUES (?,?,?,?,?,?,?)",
        (aid, alert["timestamp"], alert.get("agent", {}).get("name"),
         alert["rule"]["id"], alert["rule"]["level"], alert["rule"]["description"],
         alert.get("syscheck", {}).get("path")),
    )

    if int(alert["rule"]["level"]) >= NOTIFY_LEVEL:
        notify_alert(alert)

    indicators = extract_indicators(alert)
    if not indicators:
        log.info("Alert rule %s (level %s): no hash/public IP, VirusTotal not used",
                 alert["rule"]["id"], alert["rule"]["level"])
    for indicator, itype in indicators:
        db.execute("INSERT OR IGNORE INTO alert_indicators VALUES (?,?)", (aid, indicator))
        result = vt_lookup(db, indicator, itype)
        log.info("VirusTotal checked %s %s -> %s", itype, indicator, result)
        if result is None:
            continue
        mal, sus, verdict = result
        if verdict == "critical":
            ok = notify_discord(alert, indicator, itype, mal, sus)
            db.execute("INSERT OR IGNORE INTO notifications VALUES (?,?,?,?)",
                       (aid, indicator, time.time(), "sent" if ok else "failed"))
    db.commit()


def main():
    missing = [n for n, v in (("WAZUH_PASS", WAZUH_PASS), ("VT_API_KEY", VT_KEY),
                              ("DISCORD_WEBHOOK", DISCORD)) if not v]
    if missing:
        sys.exit(f"Missing env vars: {', '.join(missing)}")

    db = init_db()
    since = get_state(db, "last_ts", "now-5m")
    log.info("Started. Polling %s every %ss from %s", WAZUH_URL, POLL, since)

    while True:
        try:
            alerts = fetch_alerts(since)
            for a in alerts:
                process(db, a)
            if alerts:
                since = alerts[-1]["timestamp"]
                set_state(db, "last_ts", since)
            log.info("Poll done: %d alert(s)", len(alerts))
        except requests.RequestException as e:
            log.error("Network error: %s", e)
        except Exception:
            log.exception("Unexpected error")
        time.sleep(POLL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Stopped.")
