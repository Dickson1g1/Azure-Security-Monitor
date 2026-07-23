          █████╗ ███████╗██╗   ██╗██████╗ ███████╗
         ██╔══██╗╚══███╔╝██║   ██║██╔══██╗██╔════╝
         ███████║  ███╔╝ ██║   ██║██████╔╝█████╗
         ██╔══██║ ███╔╝  ██║   ██║██╔══██╗██╔══╝
         ██║  ██║███████╗╚██████╔╝██║  ██║███████╗
         ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
         
         ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
         ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
         ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
         ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
         ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
         ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝
         
          ██████╗███████╗███╗   ██╗████████╗███████╗██████╗
         ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
         ██║     █████╗  ██╔██╗ ██║   ██║   █████╗  ██████╔╝
         ██║     ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
         ╚██████╗███████╗██║ ╚████║   ██║   ███████╗██║  ██║
          ╚═════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
         
          █████╗ ██╗     ███████╗██████╗ ████████╗
         ██╔══██╗██║     ██╔════╝██╔══██╗╚══██╔══╝
         ███████║██║     █████╗  ██████╔╝   ██║
         ██╔══██║██║     ██╔══╝  ██╔══██╗   ██║
         ██║  ██║███████╗███████╗██║  ██║   ██║
         ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝
         
         ███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗
         ████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗
         ██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝
         ██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗
         ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║
         ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝

         Built by Dickson Boakye | github.com/Dickson1g1
  Azure SDK · DefaultAzureCredential · MITRE ATT&CK · Python

> Pulls Microsoft Defender for Cloud (Azure Security Center) alerts via the
> Azure SDK, filters and scores by severity, maps to MITRE ATT&CK, and
> exports structured JSON + HTML reports. Runs on a schedule or one-shot.

![Azure](https://img.shields.io/badge/Azure-Defender%20for%20Cloud-0078D4?style=flat-square&logo=microsoftazure)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## What it does

```
Azure Defender for Cloud
         ↓
  Pull alerts via SDK          ← azure-mgmt-security
         ↓
  Filter by severity           ← High / Medium / Low
         ↓
  Score and triage             ← critical path flagging
         ↓
  Map to MITRE ATT&CK          ← technique + tactic tagging
         ↓
  Export JSON + HTML report    ← SIEM-ready structured output
         ↓
  Schedule (cron / Task)       ← run every 15 min, 1 hr, daily
```

---

## Quick start

### 1. Set up Azure credentials (Service Principal)

```bash
# Install Azure CLI
az login

# Create a service principal with Security Reader role
az ad sp create-for-rbac \
  --name "security-monitor-sp" \
  --role "Security Reader" \
  --scopes /subscriptions/<YOUR_SUBSCRIPTION_ID>

# Output gives you: appId, password, tenant
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env and fill in your Azure credentials
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run

```bash
# Pull live alerts from Azure
python monitor.py

# Run with demo data (no Azure credentials needed)
python monitor.py --demo

# Filter to High severity only
python monitor.py --severity High

# Save HTML + JSON reports
python monitor.py --output reports/ --html

# Run on schedule (every 15 minutes)
python monitor.py --schedule 15

# Export to CSV for Excel
python monitor.py --demo --csv --output reports/
```

---

## Authentication methods

| Method | Best for | Setup |
|--------|----------|-------|
| Service Principal | Production, CI/CD | `.env` file with client credentials |
| Azure CLI | Local dev | `az login` then run script |
| Managed Identity | Azure-hosted scripts | No credentials needed — automatic |

The script auto-detects which method to use via `DefaultAzureCredential`.

---

## Project structure

```
azure-security-monitor/
├── monitor.py                  ← entry point
├── .env.example                ← copy to .env, add credentials
├── requirements.txt
├── core/
│   ├── azure_client.py         ← Azure SDK wrapper + auth
│   ├── alert_processor.py      ← filtering, scoring, MITRE mapping
│   └── reporter.py             ← JSON, HTML, CSV output
├── sample-data/
│   └── mock_alerts.json        ← realistic mock alerts (--demo mode)
├── output/                     ← reports saved here
└── docs/
    └── interview_answers.md
```

---

## Skills demonstrated

- Azure SDK authentication (Service Principal, DefaultAzureCredential)
- Microsoft Defender for Cloud API integration
- Security alert ingestion and enrichment pipeline
- MITRE ATT&CK technique mapping
- Scheduled monitoring with configurable intervals
- Multi-format reporting (JSON, HTML, CSV)
- Production-grade error handling and logging

---

## Author

**Dickson Boakye** — Cybersecurity Analyst | SOC | Cloud Security

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/dickson-boakye-7aa14732a/)
[![GitHub](https://img.shields.io/badge/GitHub-Dickson1g1-black?style=flat-square&logo=github)](https://github.com/Dickson1g1)
