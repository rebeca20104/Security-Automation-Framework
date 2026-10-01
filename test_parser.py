from src.ingestion import AlertIngestion
from src.parser import AlertParser


# Load alert
ingestion = AlertIngestion()

alert = ingestion.load_alert(
    "sample_alert.json"
)

# Parse alert
parser = AlertParser()

parsed_alert = parser.parse(alert)

print("[+] Alert parsed successfully")
print()

print("Alert ID:", parsed_alert["alert_id"])
print("Timestamp:", parsed_alert["timestamp"])
print("Severity:", parsed_alert["severity"])
print("Source:", parsed_alert["source"])
print("Description:", parsed_alert["description"])
