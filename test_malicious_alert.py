import os
import sys
import requests

from vt_client import enrich_indicator
from risk_engine import calculate_risk


# ============================================================
# CONFIGURATION
# ============================================================

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")


# ============================================================
# DISCORD NOTIFICATION
# ============================================================

def send_discord_alert(
    indicator_type,
    indicator,
    vt_result,
    risk,
    action
):
    """Send the VirusTotal result to Discord."""

    if not DISCORD_WEBHOOK_URL:
        print("\n[!] Discord webhook is not configured.")
        print("Set DISCORD_WEBHOOK_URL before running the test.")
        return False

    malicious = vt_result.get("malicious", 0)
    suspicious = vt_result.get("suspicious", 0)
    harmless = vt_result.get("harmless", 0)
    undetected = vt_result.get("undetected", 0)
    status = vt_result.get("status", "UNKNOWN")

    message = (
        "🚨 **SECURITY AUTOMATION ALERT**\n\n"
        f"**Indicator Type:** {indicator_type.upper()}\n"
        f"**Indicator:** `{indicator}`\n"
        f"**VirusTotal Status:** {status}\n\n"
        f"**Malicious:** {malicious}\n"
        f"**Suspicious:** {suspicious}\n"
        f"**Harmless:** {harmless}\n"
        f"**Undetected:** {undetected}\n\n"
        f"**Final Risk:** {risk}\n"
        f"**Action:** {action}"
    )

    try:
        response = requests.post(
            DISCORD_WEBHOOK_URL,
            json={"content": message},
            timeout=10
        )

        if response.status_code in (200, 204):
            print("[+] Discord notification sent successfully.")
            return True

        print(
            f"[!] Discord returned HTTP {response.status_code}"
        )
        print(response.text)
        return False

    except requests.Timeout:
        print("[!] Discord request timed out.")
        return False

    except requests.ConnectionError:
        print("[!] Could not connect to Discord.")
        return False

    except requests.RequestException as error:
        print(f"[!] Discord request failed: {error}")
        return False


# ============================================================
# GET INDICATOR TYPE
# ============================================================

def get_indicator_type():
    print("\nSelect indicator type:")
    print("1. IP address")
    print("2. Domain")
    print("3. File hash")
    print("4. Website URL")

    choice = input("\nEnter choice (1-3): ").strip()

    if choice == "1":
        return "ip"

    if choice == "2":
        return "domain"

    if choice == "3":
        return "hash"

    if choice == "4":
        return "url"
    print("[!] Invalid choice.")
    sys.exit(1)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print(" SECURITY AUTOMATION FRAMEWORK")
    print(" VirusTotal Malicious Indicator Test")
    print("=" * 60)

    # Check VirusTotal API key
    if not os.getenv("VT_API_KEY"):
        print("\n[!] VT_API_KEY is not configured.")
        print("Set it with:")
        print("export VT_API_KEY='YOUR_VIRUSTOTAL_API_KEY'")
        sys.exit(1)

    # Check Discord webhook
    if not DISCORD_WEBHOOK_URL:
        print("\n[!] DISCORD_WEBHOOK_URL is not configured.")
        print("Set it with:")
        print("export DISCORD_WEBHOOK_URL='YOUR_DISCORD_WEBHOOK_URL'")
        sys.exit(1)

    # Get indicator type
    indicator_type = get_indicator_type()

    # Get indicator value
    indicator = input(
        f"\nEnter {indicator_type} to check: "
    ).strip()

    if not indicator:
        print("[!] Indicator cannot be empty.")
        sys.exit(1)

    print("\n" + "-" * 60)
    print("Checking VirusTotal...")
    print("-" * 60)

    # ========================================================
    # VIRUSTOTAL ENRICHMENT
    # ========================================================

    vt_result = enrich_indicator(
        indicator_type,
        indicator
    )

    print("\nVirusTotal result:")
    print(vt_result)

    # ========================================================
    # RISK CALCULATION
    # ========================================================

    # For this standalone test, the local alert severity
    # is set to medium.
    local_severity = "medium"

    risk, action = calculate_risk(
        local_severity,
        vt_result
    )

    print("\n" + "-" * 60)
    print("RISK ANALYSIS")
    print("-" * 60)

    print(f"Indicator : {indicator}")
    print(f"VT Status : {vt_result.get('status')}")
    print(f"Malicious : {vt_result.get('malicious', 0)}")
    print(f"Suspicious: {vt_result.get('suspicious', 0)}")
    print(f"Risk      : {risk}")
    print(f"Action    : {action}")

    # ========================================================
    # SEND DISCORD ALERT
    # ========================================================

    print("\n" + "-" * 60)
    print("DISCORD NOTIFICATION")
    print("-" * 60)

    send_discord_alert(
        indicator_type,
        indicator,
        vt_result,
        risk,
        action
    )

    print("\n" + "=" * 60)
    print("Test completed.")
    print("=" * 60)


if __name__ == "__main__":
    main()
