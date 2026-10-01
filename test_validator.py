import json

from src.ingestion import AlertIngestion
from src.extractor import IndicatorExtractor
from src.validator import IndicatorValidator


ingestion = AlertIngestion()

alert = ingestion.load_alert(
    "sample_alert.json"
)

alert_text = json.dumps(alert)

extractor = IndicatorExtractor()

indicators = extractor.extract(
    alert_text
)

validator = IndicatorValidator()

valid_indicators = validator.validate(
    indicators
)

print("[+] IOC validation successful")
print()

print("Valid IPs:")
print(valid_indicators["ips"])

print()

print("Valid Domains:")
print(valid_indicators["domains"])

print()

print("Valid URLs:")
print(valid_indicators["urls"])

print()

print("Valid Hashes:")
print(valid_indicators["hashes"])

print()

print("Valid Emails:")
print(valid_indicators["emails"])
