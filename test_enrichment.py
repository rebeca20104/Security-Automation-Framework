from src.enrichment import VirusTotalEnricher


enricher = VirusTotalEnricher()

result = enricher.lookup_ip(
    "8.8.8.8"
)

print("[+] VirusTotal enrichment test")
print()
print(result)
