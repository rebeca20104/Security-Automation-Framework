from src.audit import AuditLogger


logger = AuditLogger()

record = {
    "alert_id": "100001",
    "source": "Wazuh",
    "risk": "MEDIUM",
    "status": "processed"
}

output = logger.save(record)

print("[+] Audit record created")
print("File:", output)
