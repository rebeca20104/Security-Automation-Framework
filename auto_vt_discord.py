
import os
import re
import json
import time
import logging
import requests

from vt_client import enrich_indicator
from risk_engine import calculate_risk


# ============================================================
# CONFIGURATION
# ============================================================

DISCORD_WEBHOOK_URL = os.getenv(
    "DISCORD_WEBHOOK_URL",
    ""
)

WAZUH_ALERT_FILE = os.getenv(
    "WAZUH_ALERT_FILE",
    "data/incoming_alert.json"
)

CHECK_INTERVAL = 5


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)


# ============================================================
# DISCORD
# ============================================================

def send_discord(
    alert_id,
    indicator_type,
    indicator,
    vt_result,
    risk,
    action
):

    if not DISCORD_WEBHOOK_URL:
        logger.error(
            "DISCORD_WEBHOOK_URL is not configured"
        )
        return False

    malicious = vt_result.get(
        "malicious",
        0
    )

    suspicious = vt_result.get(
        "suspicious",
        0
    )

    harmless = vt_result.get(
        "harmless",
        0
    )

    undetected = vt_result.get(
        "undetected",
        0
    )

    status = vt_result.get(
        "status",
        "UNKNOWN"
    )

    message = (
        "🚨 **SECURITY AUTOMATION ALERT**\n\n"
        f"**Alert ID:** `{alert_id}`\n"
        f"**Indicator Type:** `{indicator_type}`\n"
        f"**Indicator:** `{indicator}`\n\n"
        f"**VirusTotal Status:** `{status}`\n"
        f"**Malicious:** `{malicious}`\n"
        f"**Suspicious:** `{suspicious}`\n"
        f"**Harmless:** `{harmless}`\n"
        f"**Undetected:** `{undetected}`\n\n"
        f"**Final Risk:** `{risk}`\n"
        f"**Action:** `{action}`"
    )

    try:

        response = requests.post(
            DISCORD_WEBHOOK_URL,
            json={
                "content": message
            },
            timeout=10
        )

        if response.status_code in (200, 204):

            logger.info(
                "Discord notification sent successfully"
            )

            return True

        logger.error(
            "Discord returned HTTP %s",
            response.status_code
        )

        return False

    except requests.Timeout:

        logger.error(
            "Discord request timed out"
        )

        return False

    except requests.RequestException as error:

        logger.error(
            "Discord request failed: %s",
            error
        )

        return False


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text):

    if not text:
        return []

    pattern = r"https?://[^\s\"'<>]+"

    return re.findall(
        pattern,
        text
    )


# ============================================================
# IP EXTRACTION
# ============================================================

def extract_ips(text):

    if not text:
        return []

    pattern = (
        r"\b"
        r"(?:"
        r"(?:25[0-5]|2[0-4][0-9]|"
        r"[01]?[0-9][0-9]?)\."
        r"){3}"
        r"(?:25[0-5]|2[0-4][0-9]|"
        r"[01]?[0-9][0-9]?)"
        r"\b"
    )

    return re.findall(
        pattern,
        text
    )


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domains(text):

    if not text:
        return []

    pattern = (
        r"\b"
        r"(?:[a-zA-Z0-9-]+\.)+"
        r"[a-zA-Z]{2,}"
        r"\b"
    )

    return re.findall(
        pattern,
        text
    )


# ============================================================
# EXTRACT INDICATORS
# ============================================================

def extract_indicators(alert):

    indicators = []

    # --------------------------------------------------------
    # Convert complete alert to searchable text
    # --------------------------------------------------------

    try:

        alert_text = json.dumps(
            alert
        )

    except Exception:

        alert_text = str(alert)

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    urls = extract_urls(
        alert_text
    )

    for url in urls:

        indicators.append(
            {
                "type": "url",
                "value": url
            }
        )

    # --------------------------------------------------------
    # IP addresses
    # --------------------------------------------------------

    ips = extract_ips(
        alert_text
    )

    for ip in ips:

        # Ignore common local/private examples
        if ip.startswith("127."):
            continue

        indicators.append(
            {
                "type": "ip",
                "value": ip
            }
        )

    # --------------------------------------------------------
    # Domains
    # --------------------------------------------------------

    domains = extract_domains(
        alert_text
    )

    for domain in domains:

        # Avoid treating URLs as domains again
        if domain in alert_text:

            indicators.append(
                {
                    "type": "domain",
                    "value": domain
                }
            )

    # --------------------------------------------------------
    # Remove duplicates
    # --------------------------------------------------------

    unique = []

    seen = set()

    for item in indicators:

        key = (
            item["type"],
            item["value"]
        )

        if key not in seen:

            seen.add(key)
            unique.append(item)

    return unique


# ============================================================
# PROCESS ALERT
# ============================================================

def process_alert(alert):

    alert_id = alert.get(
        "id",
        alert.get(
            "alert_id",
            "UNKNOWN"
        )
    )

    severity = alert.get(
        "severity",
        "medium"
    )

    logger.info(
        "Processing alert %s",
        alert_id
    )

    logger.info(
        "Alert severity: %s",
        severity
    )

    indicators = extract_indicators(
        alert
    )

    if not indicators:

        logger.info(
            "No URL/IP/domain indicators found"
        )

        return

    logger.info(
        "Indicators found: %s",
        len(indicators)
    )

    # --------------------------------------------------------
    # Process each indicator
    # --------------------------------------------------------

    for indicator in indicators:

        indicator_type = indicator["type"]
        value = indicator["value"]

        logger.info(
            "Checking %s: %s",
            indicator_type,
            value
        )

        # ----------------------------------------------------
        # VirusTotal
        # ----------------------------------------------------

        vt_result = enrich_indicator(
            indicator_type,
            value
        )

        logger.info(
            "VirusTotal result: %s",
            vt_result
        )

        # ----------------------------------------------------
        # Risk engine
        # ----------------------------------------------------

        risk, action = calculate_risk(
            severity,
            vt_result
        )

        logger.info(
            "FINAL RISK: %s",
            risk
        )

        logger.info(
            "ACTION: %s",
            action
        )

        # ----------------------------------------------------
        # Discord
        # ----------------------------------------------------

        if risk in (
            "HIGH",
            "MEDIUM"
        ):

            send_discord(
                alert_id,
                indicator_type,
                value,
                vt_result,
                risk,
                action
            )

        else:

            logger.info(
                "Risk is LOW - Discord notification skipped"
            )


# ============================================================
# LOAD ALERT
# ============================================================

def load_alert():

    if not os.path.exists(
        WAZUH_ALERT_FILE
    ):

        return None

    try:

        with open(
            WAZUH_ALERT_FILE,
            "r"
        ) as file:

            return json.load(file)

    except json.JSONDecodeError:

        logger.error(
            "Invalid JSON in %s",
            WAZUH_ALERT_FILE
        )

        return None

    except Exception as error:

        logger.error(
            "Could not load alert: %s",
            error
        )

        return None


# ============================================================
# MAIN MONITOR
# ============================================================

def main():

    logger.info(
        "Starting automatic VirusTotal → Discord monitor"
    )

    logger.info(
        "Alert source: %s",
        WAZUH_ALERT_FILE
    )

    if not os.getenv(
        "VT_API_KEY"
    ):

        logger.error(
            "VT_API_KEY is not configured"
        )

        return

    if not DISCORD_WEBHOOK_URL:

        logger.error(
            "DISCORD_WEBHOOK_URL is not configured"
        )

        return

    logger.info(
        "VirusTotal API configured"
    )

    logger.info(
        "Discord webhook configured"
    )

    last_alert = None

    while True:

        alert = load_alert()

        if alert is not None:

            alert_string = json.dumps(
                alert,
                sort_keys=True
            )

            if alert_string != last_alert:

                process_alert(
                    alert
                )

                last_alert = alert_string

        time.sleep(
            CHECK_INTERVAL
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()

