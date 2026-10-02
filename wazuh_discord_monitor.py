import os
import json
import time
import re
import logging
import requests

from dotenv import load_dotenv
from vt_client import enrich_indicator
from risk_engine import calculate_risk

load_dotenv()

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

# Wazuh manager alert file
WAZUH_ALERT_FILE = os.getenv(
    "WAZUH_ALERT_FILE",
    "/var/ossec/logs/alerts/alerts.json"
)

CHECK_INTERVAL = 2

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# DISCORD
# ---------------------------------------------------------

def send_discord(message):

    if not DISCORD_WEBHOOK_URL:
        logger.error(
            "DISCORD_WEBHOOK_URL is not configured"
        )
        return False

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
                "Discord alert sent successfully"
            )

            return True

        logger.error(
            "Discord returned HTTP %s",
            response.status_code
        )

        return False

    except requests.RequestException as error:

        logger.error(
            "Discord request failed: %s",
            error
        )

        return False


# ---------------------------------------------------------
# INDICATOR EXTRACTION
# ---------------------------------------------------------

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

    return re.findall(pattern, text)


def extract_urls(text):

    if not text:
        return []

    pattern = r"https?://[^\s\"'<>]+"

    return re.findall(
        pattern,
        text
    )


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


# ---------------------------------------------------------
# CLASSIFY ALERT
# ---------------------------------------------------------

def classify_alert(alert):

    rule = alert.get("rule", {})

    description = str(
        rule.get(
            "description",
            ""
        )
    ).lower()

    groups = rule.get(
        "groups",
        []
    )

    groups_text = " ".join(
        str(group).lower()
        for group in groups
    )

    full_text = json.dumps(
        alert
    ).lower()

    # Authentication failures
    authentication_keywords = [
        "authentication failure",
        "failed password",
        "failed login",
        "login failure",
        "authentication failed",
        "invalid user",
        "multiple authentication failures",
        "multiple failed"
    ]

    for keyword in authentication_keywords:

        if (
            keyword in description
            or keyword in full_text
        ):

            return "AUTHENTICATION_ATTACK"

    # Malware / suspicious file
    malware_keywords = [
        "malware",
        "yara",
        "trojan",
        "virus",
        "ransomware",
        "rootkit",
        "malicious file"
    ]

    for keyword in malware_keywords:

        if (
            keyword in description
            or keyword in groups_text
            or keyword in full_text
        ):

            return "MALWARE"

    # Web attacks
    web_attack_keywords = [
        "sql injection",
        "sql_injection",
        "xss",
        "cross site scripting",
        "path traversal",
        "command injection",
        "web attack"
    ]

    for keyword in web_attack_keywords:

        if keyword in full_text:

            return "WEB_ATTACK"

    # File integrity
    if (
        "syscheck" in full_text
        or "file integrity" in full_text
    ):

        return "FILE_CHANGE"

    return "OTHER"


# ---------------------------------------------------------
# RISK
# ---------------------------------------------------------

def determine_risk(alert):

    rule = alert.get(
        "rule",
        {}
    )

    level = rule.get(
        "level",
        0
    )

    try:
        level = int(level)
    except:
        level = 0

    if level >= 10:
        return "HIGH"

    if level >= 7:
        return "MEDIUM"

    return "LOW"


# ---------------------------------------------------------
# PROCESS ALERT
# ---------------------------------------------------------

def process_alert(alert):

    alert_id = alert.get(
        "id",
        "UNKNOWN"
    )

    rule = alert.get(
        "rule",
        {}
    )

    rule_id = rule.get(
        "id",
        "UNKNOWN"
    )

    description = rule.get(
        "description",
        "Unknown event"
    )

    alert_type = classify_alert(
        alert
    )

    risk = determine_risk(
        alert
    )

    # Convert complete alert to text
    alert_text = json.dumps(
        alert
    )

    ips = list(
        set(
            extract_ips(
                alert_text
            )
        )
    )

    urls = list(
        set(
            extract_urls(
                alert_text
            )
        )
    )

    logger.info(
        "Alert %s | Type=%s | Risk=%s",
        alert_id,
        alert_type,
        risk
    )

    # -----------------------------------------------------
    # AUTHENTICATION ATTACK
    # -----------------------------------------------------

    if alert_type == "AUTHENTICATION_ATTACK":

        message = (
            "🚨 **SECURITY ALERT**\n\n"
            "**Type:** `MULTIPLE/FAILED LOGIN ATTEMPTS`\n"
            f"**Alert ID:** `{alert_id}`\n"
            f"**Rule ID:** `{rule_id}`\n"
            f"**Description:** `{description}`\n"
            f"**Risk:** `{risk}`\n"
        )

        if ips:

            message += (
                f"**Source IP:** `{ips[0]}`\n"
            )

        message += (
            "\n**Action:** `ALERT_AND_INVESTIGATE`"
        )

        send_discord(
            message
        )

        return

    # -----------------------------------------------------
    # MALWARE
    # -----------------------------------------------------

    if alert_type == "MALWARE":

        message = (
            "🦠 **MALWARE ALERT**\n\n"
            f"**Alert ID:** `{alert_id}`\n"
            f"**Rule ID:** `{rule_id}`\n"
            f"**Description:** `{description}`\n"
            f"**Risk:** `{risk}`\n"
        )

        if ips:

            message += (
                f"**Related IP:** `{ips[0]}`\n"
            )

        message += (
            "\n**Action:** `ALERT_AND_INVESTIGATE`"
        )

        send_discord(
            message
        )

        return

    # -----------------------------------------------------
    # WEB ATTACK
    # -----------------------------------------------------

    if alert_type == "WEB_ATTACK":

        message = (
            "🌐 **WEB ATTACK ALERT**\n\n"
            f"**Alert ID:** `{alert_id}`\n"
            f"**Rule ID:** `{rule_id}`\n"
            f"**Description:** `{description}`\n"
            f"**Risk:** `{risk}`\n"
        )

        if ips:

            message += (
                f"**Source IP:** `{ips[0]}`\n"
            )

        message += (
            "\n**Action:** `ALERT_AND_INVESTIGATE`"
        )

        send_discord(
            message
        )

        return

    # -----------------------------------------------------
    # URL ANALYSIS
    # -----------------------------------------------------

    for url in urls:

        logger.info(
            "Checking URL with VirusTotal: %s",
            url
        )

        try:

            vt_result = enrich_indicator(
                "url",
                url
            )

            malicious = int(
                vt_result.get(
                    "malicious",
                    0
                )
            )

            suspicious = int(
                vt_result.get(
                    "suspicious",
                    0
                )
            )

            vt_risk, action = calculate_risk(
                risk.lower(),
                vt_result
            )

            if malicious > 0:

                final_risk = "HIGH"

            elif suspicious > 0:

                final_risk = "MEDIUM"

            else:

                final_risk = risk

            if final_risk in (
                "HIGH",
                "MEDIUM"
            ):

                message = (
                    "🌐 **SUSPICIOUS URL ALERT**\n\n"
                    f"**URL:** `{url}`\n"
                    f"**Alert ID:** `{alert_id}`\n"
                    f"**Rule:** `{description}`\n\n"
                    "**VirusTotal:**\n"
                    f"Malicious: `{malicious}`\n"
                    f"Suspicious: `{suspicious}`\n\n"
                    f"**Final Risk:** `{final_risk}`\n"
                    f"**Action:** `{action}`"
                )

                send_discord(
                    message
                )

        except Exception as error:

            logger.error(
                "VirusTotal lookup failed: %s",
                error
            )


# ---------------------------------------------------------
# MONITOR WAZUH ALERTS
# ---------------------------------------------------------

def monitor_wazuh():

    logger.info(
        "Starting Wazuh → Python → VirusTotal → Discord"
    )

    logger.info(
        "Monitoring: %s",
        WAZUH_ALERT_FILE
    )

    if not os.path.exists(
        WAZUH_ALERT_FILE
    ):

        logger.error(
            "Wazuh alert file does not exist."
        )

        logger.error(
            "Check WAZUH_ALERT_FILE."
        )

        return

    with open(
        WAZUH_ALERT_FILE,
        "r"
    ) as file:

        # Start from current end of file.
        # New Wazuh alerts will be processed.
        file.seek(
            0,
            2
        )

        logger.info(
            "Waiting for new Wazuh alerts..."
        )

        while True:

            line = file.readline()

            if not line:

                time.sleep(
                    CHECK_INTERVAL
                )

                continue

            line = line.strip()

            if not line:
                continue

            try:

                alert = json.loads(
                    line
                )

                process_alert(
                    alert
                )

            except json.JSONDecodeError:

                logger.warning(
                    "Invalid JSON alert received."
                )

            except Exception as error:

                logger.error(
                    "Alert processing error: %s",
                    error
                )


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

if __name__ == "__main__":

    if not DISCORD_WEBHOOK_URL:

        logger.error(
            "DISCORD_WEBHOOK_URL is not configured."
        )

        raise SystemExit(1)

    if not os.getenv(
        "VT_API_KEY"
    ):

        logger.warning(
            "VT_API_KEY is not configured."
        )

        logger.warning(
            "VirusTotal URL enrichment will not work."
        )

    monitor_wazuh()
