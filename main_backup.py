import os
import json
import sqlite3
import ipaddress
import re
import base64
import logging
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()

DISCORD_WEBHOOK_URL = os.getenv(
    "DISCORD_WEBHOOK_URL", ""
).strip()

SOAR_WEBHOOK_URL = os.getenv(
    "SOAR_WEBHOOK_URL", ""
).strip()

VT_TIMEOUT = 10

DB_FILE = "incidents.db"

CACHE_FILE = "data/vt_cache.json"

SUPPORTED_TYPES = {
    "ip",
    "domain",
    "url",
    "sha256"
}


# ============================================================
# LOGGING
# ============================================================

Path("logs").mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/automation.log")
    ]
)

logger = logging.getLogger("security-automation")


# ============================================================
# DATABASE
# ============================================================

def init_database():

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            alert_id TEXT,

            indicator TEXT,

            indicator_type TEXT,

            local_risk TEXT,

            vt_malicious INTEGER,

            vt_suspicious INTEGER,

            vt_harmless INTEGER,

            vt_status TEXT,

            final_risk TEXT,

            action TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_incident(data):

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO incidents
        (
            timestamp,
            alert_id,
            indicator,
            indicator_type,
            local_risk,
            vt_malicious,
            vt_suspicious,
            vt_harmless,
            vt_status,
            final_risk,
            action
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (

        data["timestamp"],
        data["alert_id"],
        data["indicator"],
        data["indicator_type"],
        data["local_risk"],
        data["vt_malicious"],
        data["vt_suspicious"],
        data["vt_harmless"],
        data["vt_status"],
        data["final_risk"],
        data["action"]
    ))

    connection.commit()
    connection.close()


# ============================================================
# INPUT VALIDATION
# ============================================================

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)

SHA256_REGEX = re.compile(
    r"^[A-Fa-f0-9]{64}$"
)


def validate_indicator(indicator):

    if not isinstance(indicator, dict):

        return None, "INVALID_INDICATOR"


    indicator_type = str(
        indicator.get("type", "")
    ).lower().strip()


    value = str(
        indicator.get("value", "")
    ).strip()


    if indicator_type not in SUPPORTED_TYPES:

        return None, "INVALID_TYPE"


    if not value:

        return None, "EMPTY_VALUE"


    try:

        if indicator_type == "ip":

            ipaddress.ip_address(value)


        elif indicator_type == "domain":

            if not DOMAIN_REGEX.match(value):

                raise ValueError("Invalid domain")


        elif indicator_type == "url":

            parsed = urlparse(value)

            if parsed.scheme not in [
                "http",
                "https"
            ]:

                raise ValueError("Invalid URL")

            if not parsed.netloc:

                raise ValueError("Invalid URL")


        elif indicator_type == "sha256":

            if not SHA256_REGEX.match(value):

                raise ValueError("Invalid SHA256")


    except ValueError:

        return None, "INVALID_FORMAT"


    return {
        "type": indicator_type,
        "value": value
    }, None


# ============================================================
# LOAD ALERT
# ============================================================

def load_alert(filename):

    try:

        with open(
            filename,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)


    except FileNotFoundError:

        logger.error(
            "Alert file not found: %s",
            filename
        )

        return None


    except json.JSONDecodeError:

        logger.error(
            "Alert JSON is invalid"
        )

        return None


# ============================================================
# LOCAL RULE ENGINE
# ============================================================

def local_risk(severity):

    severity = str(
        severity
    ).lower()


    if severity in [
        "critical",
        "high"
    ]:

        return "HIGH"


    if severity == "medium":

        return "MEDIUM"


    return "LOW"


# ============================================================
# VIRUSTOTAL CACHE
# ============================================================

def load_cache():

    if not os.path.exists(CACHE_FILE):

        return {}


    try:

        with open(
            CACHE_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)


    except Exception:

        return {}


def save_cache(cache):

    Path("data").mkdir(
        exist_ok=True
    )

    with open(
        CACHE_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            cache,
            file,
            indent=4
        )


# ============================================================
# VIRUSTOTAL ENDPOINT
# ============================================================

def get_vt_endpoint(
    indicator_type,
    value
):

    if indicator_type == "domain":

        return (
            "https://www.virustotal.com/"
            f"api/v3/domains/{value}"
        )


    if indicator_type == "ip":

        return (
            "https://www.virustotal.com/"
            f"api/v3/ip_addresses/{value}"
        )


    if indicator_type == "sha256":

        return (
            "https://www.virustotal.com/"
            f"api/v3/files/{value}"
        )


    if indicator_type == "url":

        encoded = base64.urlsafe_b64encode(
            value.encode()
        ).decode().rstrip("=")

        return (
            "https://www.virustotal.com/"
            f"api/v3/urls/{encoded}"
        )


    raise ValueError(
        "Unsupported indicator"
    )


# ============================================================
# VIRUSTOTAL LOOKUP
# ============================================================

def virustotal_lookup(indicator):

    indicator_type = indicator["type"]

    value = indicator["value"]

    cache_key = (
        f"{indicator_type}:{value}"
    )


    cache = load_cache()


    if cache_key in cache:

        logger.info(
            "Using cached VT result for %s",
            value
        )

        return cache[cache_key]


    if not VT_API_KEY:

        logger.warning(
            "VirusTotal API key not configured"
        )

        return {
            "indicator": value,
            "type": indicator_type,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "status": "NO_API_KEY"
        }


    url = get_vt_endpoint(
        indicator_type,
        value
    )


    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json"
    }


    try:

        logger.info(
            "VirusTotal lookup: %s",
            value
        )


        response = requests.get(
            url,
            headers=headers,
            timeout=VT_TIMEOUT
        )


        if response.status_code == 401:

            return {
                "indicator": value,
                "type": indicator_type,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "status": "UNAUTHORIZED"
            }


        if response.status_code == 429:

            return {
                "indicator": value,
                "type": indicator_type,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "status": "RATE_LIMITED"
            }


        if response.status_code == 404:

            return {
                "indicator": value,
                "type": indicator_type,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "status": "NOT_FOUND"
            }


        response.raise_for_status()


        result_json = response.json()


        attributes = (
            result_json
            .get("data", {})
            .get("attributes", {})
        )


        statistics = (
            attributes
            .get("last_analysis_stats", {})
        )


        result = {

            "indicator": value,

            "type": indicator_type,

            "malicious": int(
                statistics.get(
                    "malicious",
                    0
                )
            ),

            "suspicious": int(
                statistics.get(
                    "suspicious",
                    0
                )
            ),

            "harmless": int(
                statistics.get(
                    "harmless",
                    0
                )
            ),

            "status": "OK"
        }


        cache[cache_key] = result

        save_cache(cache)


        return result


    except requests.RequestException as error:

        logger.error(
            "VirusTotal request failed: %s",
            error
        )


        return {

            "indicator": value,

            "type": indicator_type,

            "malicious": 0,

            "suspicious": 0,

            "harmless": 0,

            "status": "NETWORK_ERROR"
        }


# ============================================================
# FINAL RISK ENGINE
# ============================================================

def calculate_final_risk(
    severity,
    vt_results
):

    severity = str(
        severity
    ).lower()


    if severity == "critical":

        return "HIGH"


    if severity == "high":

        return "HIGH"


    malicious = max(
        [
            result.get(
                "malicious",
                0
            )
            for result in vt_results
        ],
        default=0
    )


    suspicious = max(
        [
            result.get(
                "suspicious",
                0
            )
            for result in vt_results
        ],
        default=0
    )


    if malicious >= 5:

        return "HIGH"


    if malicious > 0:

        return "MEDIUM"


    if suspicious > 0:

        return "MEDIUM"


    return "LOW"


# ============================================================
# ACTION ROUTING
# ============================================================

def determine_action(
    final_risk
):

    if final_risk == "HIGH":

        return "CREATE_TICKET_AND_NOTIFY"


    if final_risk == "MEDIUM":

        return "REVIEW_AND_NOTIFY"


    return "LOG_ONLY"


# ============================================================
# SOAR WEBHOOK
# ============================================================

def send_to_soar(payload):

    if not SOAR_WEBHOOK_URL:

        logger.info(
            "SOAR webhook not configured"
        )

        return


    try:

        response = requests.post(
            SOAR_WEBHOOK_URL,
            json=payload,
            timeout=10
        )


        logger.info(
            "SOAR response: HTTP %s",
            response.status_code
        )


    except requests.RequestException as error:

        logger.error(
            "SOAR request failed: %s",
            error
        )


# ============================================================
# DISCORD
# ============================================================

def send_discord(
    alert_id,
    indicator,
    final_risk,
    malicious,
    action
):

    if not DISCORD_WEBHOOK_URL:

        logger.info(
            "Discord webhook not configured"
        )

        return


    message = (
        f"🚨 SECURITY ALERT\n\n"
        f"Alert: {alert_id}\n"
        f"Indicator: {indicator}\n"
        f"Risk: {final_risk}\n"
        f"VT malicious: {malicious}\n"
        f"Action: {action}"
    )


    try:

        response = requests.post(

            DISCORD_WEBHOOK_URL,

            json={
                "content": message
            },

            timeout=10
        )


        logger.info(
            "Discord response: HTTP %s",
            response.status_code
        )


    except requests.RequestException as error:

        logger.error(
            "Discord failed: %s",
            error
        )


# ============================================================
# MAIN PIPELINE
# ============================================================

def process_alert(
    filename
):

    logger.info(
        "Starting Security Automation Framework"
    )


    alert = load_alert(
        filename
    )


    if alert is None:

        return


    logger.info(
        "Alert loaded"
    )


    # --------------------------------------------------------
    # Extract alert information
    # --------------------------------------------------------

    alert_id = str(
        alert.get(
            "alert_id",
            alert.get(
                "id",
                "UNKNOWN"
            )
        )
    )


    severity = str(
        alert.get(
            "severity",
            "low"
        )
    ).lower()


    indicators = alert.get(
        "indicators",
        []
    )


    logger.info(
        "Alert ID: %s",
        alert_id
    )


    logger.info(
        "Severity: %s",
        severity
    )


    # --------------------------------------------------------
    # Indicator validation
    # --------------------------------------------------------

    valid_indicators = []


    for indicator in indicators:

        clean, error = (
            validate_indicator(
                indicator
            )
        )


        if error:

            logger.warning(
                "Invalid indicator: %s",
                error
            )

            continue


        valid_indicators.append(
            clean
        )


    if not valid_indicators:

        logger.warning(
            "No valid indicators"
        )

        return


    # --------------------------------------------------------
    # Local risk
    # --------------------------------------------------------

    local_result = local_risk(
        severity
    )


    logger.info(
        "Local rule result: %s",
        local_result
    )


    # --------------------------------------------------------
    # VirusTotal
    # --------------------------------------------------------

    vt_results = []


    for indicator in valid_indicators:

        result = virustotal_lookup(
            indicator
        )

        vt_results.append(
            result
        )


    # --------------------------------------------------------
    # Final risk
    # --------------------------------------------------------

    final_result = calculate_final_risk(
        severity,
        vt_results
    )


    action = determine_action(
        final_result
    )


    logger.info(
        "FINAL RISK: %s",
        final_result
    )


    logger.info(
        "ACTION: %s",
        action
    )


    # --------------------------------------------------------
    # SOAR
    # --------------------------------------------------------

    soar_payload = {

        "alert_id": alert_id,

        "severity": severity,

        "local_risk": local_result,

        "final_risk": final_result,

        "action": action,

        "indicators": valid_indicators,

        "virustotal": vt_results
    }


    send_to_soar(
        soar_payload
    )


    # --------------------------------------------------------
    # SQLite + Discord
    # --------------------------------------------------------

    for indicator, vt in zip(
        valid_indicators,
        vt_results
    ):

        database_row = {

            "timestamp":
                alert.get(
                    "timestamp",
                    ""
                ),

            "alert_id":
                alert_id,

            "indicator":
                indicator["value"],

            "indicator_type":
                indicator["type"],

            "local_risk":
                local_result,

            "vt_malicious":
                vt.get(
                    "malicious",
                    0
                ),

            "vt_suspicious":
                vt.get(
                    "suspicious",
                    0
                ),

            "vt_harmless":
                vt.get(
                    "harmless",
                    0
                ),

            "vt_status":
                vt.get(
                    "status",
                    "UNKNOWN"
                ),

            "final_risk":
                final_result,

            "action":
                action
        }


        save_incident(
            database_row
        )


        if final_result in [
            "HIGH",
            "MEDIUM"
        ]:

            send_discord(

                alert_id,

                indicator["value"],

                final_result,

                vt.get(
                    "malicious",
                    0
                ),

                action
            )


    logger.info(
        "Automation completed successfully"
    )


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    init_database()

    input_file = (
        "data/sample_alert.json"
    )

    process_alert(
        input_file
    )
from vt_client import enrich_indicator

indicator = {
    "type": "domain",
    "value": "example.com"
}

result = enrich_indicator(
    indicator["type"],
    indicator["value"]
)

print("Enrichment result:")
print(result)
import json

from vt_client import enrich_indicator
from risk_engine import calculate_risk


with open("sample_alert.json", "r") as file:
    alert = json.load(file)


print("Alert ID:", alert["alert_id"])
print("Wazuh Severity:", alert["severity"])
print()


for indicator in alert["indicators"]:

    indicator_type = indicator["type"]
    value = indicator["value"]

    print(f"Enriching {indicator_type}: {value}")

    vt_result = enrich_indicator(
        indicator_type,
        value
    )

    final_risk = calculate_risk(
        alert["severity"],
        vt_result
    )

    print("VirusTotal Result:")
    print(vt_result)

    print("FINAL RISK:", final_risk)

    print("-" * 50)
