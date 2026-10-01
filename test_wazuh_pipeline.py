import json

from src.ingestion import AlertIngestion
from src.parser import AlertParser
from src.extractor import IndicatorExtractor
from src.validator import IndicatorValidator
from src.decision import RiskEngine


ingestion = AlertIngestion()

alert = ingestion.load_alert(
    "wazuh_alert.json"
)

ingestion.validate_alert_structure(alert)

parser = AlertParser()
parsed = parser.parse(alert)

extractor = IndicatorExtractor()

alert_text = json.dumps(alert)

indicators = extractor.extract(
    alert_text
)

validator = IndicatorValidator()

valid_indicators = validator.validate(
    indicators
)

risk_engine = RiskEngine()

risk = risk_engine.calculate(
    alert,
    valid_indicators
)

print("[+] Wazuh alert loaded")
print("[+] Wazuh alert validated")
print("[+] Wazuh alert parsed")
print("[+] Indicators extracted")
print("[+] Indicators validated")
print("[+] Risk calculated")
print()

print("========== PARSED ALERT ==========")
print("Alert ID:", parsed["alert_id"])
print("Source:", parsed["source"])
print("Rule ID:", parsed["rule_id"])
print("Rule Description:", parsed["rule_description"])
print("Agent:", parsed["agent_name"])
print("Agent IP:", parsed["agent_ip"])
print("Severity:", parsed["severity"])

print()
print("========== INDICATORS ==========")
print("IPs:", valid_indicators["ips"])
print("Domains:", valid_indicators["domains"])
print("URLs:", valid_indicators["urls"])
print("Hashes:", valid_indicators["hashes"])
print("Emails:", valid_indicators["emails"])

print()
print("========== RISK ==========")
print("Risk:", risk["risk"])
print("Wazuh Level:", risk["wazuh_level"])
print("Indicator Count:", risk["indicator_count"])
