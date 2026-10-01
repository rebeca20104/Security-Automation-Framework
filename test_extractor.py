import json

from src.ingestion import AlertIngestion
from src.extractor import IndicatorExtractor


ingestion = AlertIngestion()

alert = ingestion.load_alert(
    "sample_alert.json"
)

alert_text = json.dumps(alert)

extractor = IndicatorExtractor()

indicators = extractor.extract(
    alert_text
)

print("[+] IOC extraction successful")
print()

print("IP Addresses:")
print(indicators["ips"])

print()

print("Domains:")
print(indicators["domains"])

print()

print("URLs:")
print(indicators["urls"])

print()

print("Hashes:")
print(indicators["hashes"])

print()

print("Email Addresses:")
print(indicators["emails"])

