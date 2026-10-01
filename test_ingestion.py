from src.ingestion import AlertIngestion


ingestion = AlertIngestion()

alert = ingestion.load_alert(
    "sample_alert.json"
)

ingestion.validate_alert_structure(alert)

print("[+] Alert successfully loaded")
print()
print("Alert ID:", alert["alert_id"])
print("Severity:", alert["severity"])
print("Description:", alert["description"])
