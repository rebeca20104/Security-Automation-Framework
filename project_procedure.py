import os
import subprocess
import sys


PROJECT = os.path.expanduser(
    "~/security-automation-framework"
)


def show_step(number, title, description):
    print("\n" + "=" * 70)
    print(f"STEP {number}: {title}")
    print("=" * 70)
    print(description)


def main():

    print("\n")
    print("=" * 70)
    print("       SECURITY AUTOMATION FRAMEWORK")
    print("=" * 70)

    print("""
Project workflow:

Wazuh
   ↓
Alert Receiver
   ↓
Alert Ingestion
   ↓
Alert Parser
   ↓
IOC Extraction
   ↓
IOC Validation
   ↓
VirusTotal Enrichment
   ↓
Decision Engine
   ↓
Audit Report
   ↓
Discord / Slack Notification
""")

    show_step(
        1,
        "WAZUH ALERT",
        "Wazuh detects a security event and generates a JSON alert."
    )

    show_step(
        2,
        "PYTHON RECEIVER",
        "wazuh_receiver.py receives the Wazuh alert using HTTP POST."
    )

    show_step(
        3,
        "ALERT INGESTION",
        "The ingestion module loads and validates the alert structure."
    )

    show_step(
        4,
        "ALERT PARSING",
        "The parser converts the raw alert into a normalized format."
    )

    show_step(
        5,
        "IOC EXTRACTION",
        "The framework extracts IP addresses, domains, URLs, hashes and emails."
    )

    show_step(
        6,
        "IOC VALIDATION",
        "Extracted indicators are checked for valid formats."
    )

    show_step(
        7,
        "VIRUSTOTAL ENRICHMENT",
        "File hashes can be checked against VirusTotal."
    )

    show_step(
        8,
        "DECISION ENGINE",
        "The framework classifies enrichment results and determines an action."
    )

    show_step(
        9,
        "AUDIT",
        "The complete processing result is saved as a JSON audit report."
    )

    show_step(
        10,
        "NOTIFICATION",
        "Important results can be sent to Discord or Slack."
    )

    print("\n" + "=" * 70)
    print("PROJECT PROCEDURE COMPLETED")
    print("=" * 70)


if __name__ == "__main__":
    main()
