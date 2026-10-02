import os
import sys
import time
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

BASE_URL = "https://www.virustotal.com/api/v3"

if not API_KEY:
    print("[ERROR] VT_API_KEY is not configured.")
    sys.exit(1)

if not DISCORD_WEBHOOK_URL:
    print("[ERROR] DISCORD_WEBHOOK_URL is not configured.")
    sys.exit(1)

HEADERS = {
    "x-apikey": API_KEY,
    "accept": "application/json"
}


def send_discord_alert(
    indicator_type,
    indicator,
    malicious,
    suspicious,
    harmless,
    undetected,
    risk
):
    if risk == "HIGH":
        emoji = "🔴"
    elif risk == "MEDIUM":
        emoji = "🟠"
    else:
        emoji = "🟢"

    message = (
        f"{emoji} **SECURITY AUTOMATION ALERT**\n\n"
        f"**Indicator Type:** `{indicator_type}`\n"
        f"**Indicator:** `{indicator}`\n\n"
        f"**VirusTotal Results:**\n"
        f"Malicious: `{malicious}`\n"
        f"Suspicious: `{suspicious}`\n"
        f"Harmless: `{harmless}`\n"
        f"Undetected: `{undetected}`\n\n"
        f"**Risk Level:** `{risk}`"
    )

    try:
        response = requests.post(
            DISCORD_WEBHOOK_URL,
            json={"content": message},
            timeout=10
        )

        if response.status_code in (200, 204):
            print("[+] Discord alert sent successfully.")
            return True

        print(
            f"[!] Discord returned HTTP "
            f"{response.status_code}"
        )
        return False

    except requests.RequestException as error:
        print(f"[!] Discord notification failed: {error}")
        return False


def calculate_risk(malicious, suspicious):
    if malicious > 0:
        return "HIGH"

    if suspicious > 0:
        return "MEDIUM"

    return "LOW"


def print_result(
    name,
    data,
    indicator_type
):
    attributes = data.get(
        "data",
        {}
    ).get(
        "attributes",
        {}
    )

    stats = attributes.get(
        "last_analysis_stats",
        {}
    )

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    risk = calculate_risk(
        malicious,
        suspicious
    )

    print("\n" + "=" * 60)
    print("VIRUSTOTAL RESULT")
    print("=" * 60)

    print(f"Indicator : {name}")
    print(f"Type      : {indicator_type}")
    print(f"Malicious : {malicious}")
    print(f"Suspicious: {suspicious}")
    print(f"Harmless  : {harmless}")
    print(f"Undetected: {undetected}")
    print(f"\nRISK: {risk}")

    print("=" * 60)

    send_discord_alert(
        indicator_type,
        name,
        malicious,
        suspicious,
        harmless,
        undetected,
        risk
    )


def check_domain(domain):
    url = f"{BASE_URL}/domains/{domain}"

    print(f"\n[+] Checking domain: {domain}")

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=15
        )
    except requests.RequestException as error:
        print(f"[!] Request failed: {error}")
        return

    if response.status_code == 404:
        print("[!] Domain not found in VirusTotal.")
        return

    if response.status_code != 200:
        print(
            f"[!] VirusTotal error: "
            f"HTTP {response.status_code}"
        )
        return

    print_result(
        domain,
        response.json(),
        "DOMAIN"
    )


def check_ip(ip):
    url = f"{BASE_URL}/ip_addresses/{ip}"

    print(f"\n[+] Checking IP: {ip}")

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=15
        )
    except requests.RequestException as error:
        print(f"[!] Request failed: {error}")
        return

    if response.status_code == 404:
        print("[!] IP not found in VirusTotal.")
        return

    if response.status_code != 200:
        print(
            f"[!] VirusTotal error: "
            f"HTTP {response.status_code}"
        )
        return

    print_result(
        ip,
        response.json(),
        "IP"
    )


def check_hash(file_hash):
    url = f"{BASE_URL}/files/{file_hash}"

    print(f"\n[+] Checking file hash: {file_hash}")

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=15
        )
    except requests.RequestException as error:
        print(f"[!] Request failed: {error}")
        return

    if response.status_code == 404:
        print("[!] File hash not found in VirusTotal.")
        return

    if response.status_code != 200:
        print(
            f"[!] VirusTotal error: "
            f"HTTP {response.status_code}"
        )
        return

    print_result(
        file_hash,
        response.json(),
        "FILE HASH"
    )


def check_url(target_url):
    url = f"{BASE_URL}/urls"

    print(f"\n[+] Checking URL: {target_url}")

    try:
        response = requests.post(
            url,
            headers=HEADERS,
            data={"url": target_url},
            timeout=15
        )
    except requests.RequestException as error:
        print(f"[!] URL submission failed: {error}")
        return

    if response.status_code != 200:
        print(
            f"[!] URL submission failed: "
            f"HTTP {response.status_code}"
        )
        return

    analysis_id = response.json()["data"]["id"]

    print("\n[+] URL submitted to VirusTotal")
    print(f"[+] Analysis ID: {analysis_id}")
    print("[+] Waiting for analysis...")

    analysis_url = (
        f"{BASE_URL}/analyses/{analysis_id}"
    )

    for attempt in range(50):

        try:
            response = requests.get(
                analysis_url,
                headers=HEADERS,
                timeout=15
            )
        except requests.RequestException as error:
            print(f"[!] Analysis request failed: {error}")
            return

        if response.status_code != 200:
            print(
                f"[!] Analysis request failed: "
                f"HTTP {response.status_code}"
            )
            return

        data = response.json()

        attributes = data.get(
            "data",
            {}
        ).get(
            "attributes",
            {}
        )

        status = attributes.get(
            "status",
            "unknown"
        )

        print(
            f"[+] Analysis status: {status}"
        )

        if status == "completed":

            stats = attributes.get(
                "stats",
                {}
            )

            malicious = stats.get(
                "malicious",
                0
            )

            suspicious = stats.get(
                "suspicious",
                0
            )

            harmless = stats.get(
                "harmless",
                0
            )

            undetected = stats.get(
                "undetected",
                0
            )

            risk = calculate_risk(
                malicious,
                suspicious
            )

            print("\n" + "=" * 60)
            print("VIRUSTOTAL URL RESULT")
            print("=" * 60)

            print(
                f"URL        : {target_url}"
            )

            print(
                f"Malicious  : {malicious}"
            )

            print(
                f"Suspicious : {suspicious}"
            )

            print(
                f"Harmless   : {harmless}"
            )

            print(
                f"Undetected : {undetected}"
            )

            print(
                f"\nRISK: {risk}"
            )

            print("=" * 60)

            send_discord_alert(
                "URL",
                target_url,
                malicious,
                suspicious,
                harmless,
                undetected,
                risk
            )

            return

        time.sleep(15)

    print(
        "[!] Analysis did not complete "
        "within the timeout."
    )


def upload_file(file_path):

    if not os.path.isfile(file_path):
        print("[!] File does not exist.")
        return

    file_size = os.path.getsize(file_path)

    print(f"\n[+] File: {file_path}")
    print(f"[+] Size: {file_size} bytes")

    if file_size > 32 * 1024 * 1024:
        print(
            "[!] File is larger than 32 MB."
        )
        return

    url = f"{BASE_URL}/files"

    try:
        with open(file_path, "rb") as file:

            response = requests.post(
                url,
                headers={
                    "x-apikey": API_KEY,
                    "accept": "application/json"
                },
                files={
                    "file": file
                },
                timeout=60
            )

    except requests.RequestException as error:
        print(
            f"[!] Upload failed: {error}"
        )
        return

    if response.status_code != 200:
        print(
            f"[!] VirusTotal upload failed: "
            f"HTTP {response.status_code}"
        )
        return

    result = response.json()

    analysis_id = result["data"]["id"]

    print(
        "\n[+] File uploaded successfully"
    )

    print(
        f"[+] Analysis ID: {analysis_id}"
    )

    print(
        "[+] Waiting for VirusTotal analysis..."
    )

    analysis_url = (
        f"{BASE_URL}/analyses/{analysis_id}"
    )

    for attempt in range(12):

        try:
            response = requests.get(
                analysis_url,
                headers=HEADERS,
                timeout=15
            )
        except requests.RequestException as error:
            print(
                f"[!] Analysis request failed: {error}"
            )
            return

        if response.status_code != 200:
            print(
                f"[!] Analysis request failed: "
                f"HTTP {response.status_code}"
            )
            return

        data = response.json()

        attributes = data.get(
            "data",
            {}
        ).get(
            "attributes",
            {}
        )

        status = attributes.get(
            "status",
            "unknown"
        )

        print(
            f"[+] Analysis status: {status}"
        )

        if status == "completed":

            stats = attributes.get(
                "stats",
                {}
            )

            malicious = stats.get(
                "malicious",
                0
            )

            suspicious = stats.get(
                "suspicious",
                0
            )

            harmless = stats.get(
                "harmless",
                0
            )

            undetected = stats.get(
                "undetected",
                0
            )

            risk = calculate_risk(
                malicious,
                suspicious
            )

            print("\n" + "=" * 60)
            print("VIRUSTOTAL FILE RESULT")
            print("=" * 60)

            print(
                f"File       : {file_path}"
            )

            print(
                f"Malicious  : {malicious}"
            )

            print(
                f"Suspicious : {suspicious}"
            )

            print(
                f"Harmless   : {harmless}"
            )

            print(
                f"Undetected : {undetected}"
            )

            print(
                f"\nRISK: {risk}"
            )

            print("=" * 60)

            send_discord_alert(
                "LOCAL FILE",
                file_path,
                malicious,
                suspicious,
                harmless,
                undetected,
                risk
            )

            return

        time.sleep(5)

    print(
        "[!] File analysis did not complete "
        "within the timeout."
    )


def menu():

    print("\n" + "=" * 60)
    print(" SECURITY AUTOMATION FRAMEWORK")
    print(" VirusTotal Risk Checker")
    print("=" * 60)

    print("\n1. Domain")
    print("2. URL")
    print("3. IP address")
    print("4. File hash")
    print("5. Local file")

    choice = input(
        "\nSelect option (1-5): "
    ).strip()

    if choice == "1":

        domain = input(
            "Enter domain: "
        ).strip()

        check_domain(domain)

    elif choice == "2":

        target_url = input(
            "Enter URL: "
        ).strip()

        check_url(target_url)

    elif choice == "3":

        ip = input(
            "Enter IP address: "
        ).strip()

        check_ip(ip)

    elif choice == "4":

        file_hash = input(
            "Enter MD5/SHA1/SHA256 hash: "
        ).strip()

        check_hash(file_hash)

    elif choice == "5":

        file_path = input(
            "Enter local file path: "
        ).strip()

        upload_file(file_path)

    else:

        print("[!] Invalid option.")


if __name__ == "__main__":
    menu()
