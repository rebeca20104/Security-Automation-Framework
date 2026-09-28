# Security-Automation-Framework

Automated security alert triage and threat-intelligence enrichment.

**Pipeline:** Wazuh → Python ingestion → validation → local rules → VirusTotal → risk engine → Shuffle/Tines → Slack/Discord → audit log

> Status: work in progress. Only synthetic or lab data is used. No real credentials or customer data.

## Objective
Reduce repetitive manual SOC work (read alert, copy indicator, look it up, judge severity, notify, document) to a single automated run with an auditable record.

## Progress
| Phase | Work | Status |
|---|---|---|
| 1 | Wazuh manager + Kali agent, generate authentication-failure alerts | Done |
| 2 | Wazuh alert adapter (JSON Lines to framework format), severity mapping, noise filter | Done |
| 3 | Input validation + local rules | Next |
| 4 | VirusTotal enrichment (caching, rate limits) + risk engine | Planned |
| 5 | Slack/Discord notification | Planned |
| 6 | Shuffle/Tines workflow | Planned |
| 7 | SQLite audit log, dashboard, testing, report | Planned |

## What works today
- Wazuh agent (Kali) reporting to the manager; failed `su` logins detected (rules 5301, 5503, 5557, MITRE T1110.001).
- `src/wazuh_adapter.py` converts Wazuh alerts to the framework format:
  - level 0-4 = low, 5-7 = medium, 8-11 = high, 12+ = critical
  - alerts below level 5 are filtered as noise
  - only **public** IPs become indicators (private IPs are useless for VirusTotal)

## Layout
```
data/         anonymized real Wazuh alerts (JSON Lines)
src/          wazuh_adapter.py (more modules coming)
tests/        pytest unit tests
docs/         setup and validation notes
screenshots/  evidence (add yours)
```

## Run
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 src/wazuh_adapter.py data/wazuh_alerts_sample.json
pytest
```

## Known limitation
Local `su` failures have no source IP, so they cannot be enriched. Next step: generate an SSH-style failed login with a public source IP in the lab to exercise the enrichment path.

## Security
Secrets live in `.env` (see `.env.example`), which is git-ignored. Sample data is anonymized.
