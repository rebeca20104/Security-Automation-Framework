from vt_client import enrich_indicator


result = enrich_indicator(
    "ip",
    "8.8.8.8"
)

print("VirusTotal IP enrichment result:")
print(result)
