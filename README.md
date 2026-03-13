# SOCratic 🔍
> AI-powered SOC alert triage assistant — built by a SOC analyst, for SOC analysts.

![SOCratic Dashboard](docs/screenshot.png)

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Groq](https://img.shields.io/badge/Groq-LLaMA_3.3_70B-F55036?style=flat)](https://groq.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-CC0000?style=flat)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)

---

## The Problem

SOC analysts face an average of **960 alerts per day**. Over 40% are false positives. Tier-1 analysts spend more time reading and formatting than actually investigating — context-switching between SIEM dashboards, MITRE ATT&CK docs, and runbooks just to triage a single alert.

**SOCratic fixes this.**

Paste any raw alert. Get a full analysis in seconds.

---

## Demo

| Input | Output |
|---|---|
| Raw Wazuh / Splunk / ELK alert | Plain-English explanation |
| Any SIEM format | False positive score (0–100) |
| JSON, syslog, CEF | MITRE ATT&CK technique mapping |
| — | Prioritized investigation steps |
| — | Extracted IOCs & affected assets |

---

## Features

- 🧠 **Alert Explainer** — converts raw SIEM output into plain English instantly
- 🎯 **False Positive Scorer** — 0–100 probability score with evidence-based reasoning
- 🗺️ **MITRE ATT&CK Mapper** — auto-tags techniques (T-IDs), tactics, and confidence scores with direct ATT&CK links
- 🔍 **Investigation Runbook** — context-aware next steps prioritized as Immediate / High / Medium
- 🌐 **IOC Extractor** — pulls IPs, domains, hashes automatically from alert text
- 🔌 **Multi-SIEM Support** — Wazuh, Splunk, ELK, FortiSIEM, or raw manual paste
- ⚡ **Sub-2s responses** — powered by Groq's LLaMA 3.3 70B inference

---

## Quick Start

### Prerequisites
- Python 3.11+
- Free [Groq API key](https://console.groq.com) (no credit card required)

### Run in 3 steps

```bash
# 1. Clone and install
git clone https://github.com/aavashcsit/socratic
cd socratic/backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Add your GROQ_API_KEY to .env

# 3. Start
uvicorn app.main:app --reload
```

Open the frontend:
```bash
cd ../frontend
python -m http.server 3000
# Visit http://localhost:3000
```

No Docker. No database setup. No paid API required.

---

## Architecture

```
socratic/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app + CORS
│   │   ├── api/routes/
│   │   │   └── analysis.py      # 5 REST endpoints
│   │   ├── services/
│   │   │   └── analysis.py      # Groq/Anthropic AI logic
│   │   ├── models/
│   │   │   └── schemas.py       # Pydantic request/response models
│   │   ├── prompts/
│   │   │   └── templates.py     # Tuned SOC-specific prompts
│   │   └── core/
│   │       └── config.py        # Environment + settings
│   └── tests/
│       └── test_analysis.py     # pytest test suite
└── frontend/
    └── index.html               # Zero-dependency dashboard UI
```

---

## API Reference

Base URL: `http://localhost:8000`

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/analyze` | POST | Full analysis — all features |
| `/api/v1/explain` | POST | Plain-English explanation only |
| `/api/v1/score` | POST | False positive score only |
| `/api/v1/mitre` | POST | MITRE ATT&CK mapping only |
| `/api/v1/health` | GET | Health check + model info |

Interactive docs: `http://localhost:8000/docs`

### Example Request

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "raw_alert": "{\"rule\":{\"level\":10,\"description\":\"Multiple authentication failures\"},\"data\":{\"srcip\":\"203.0.113.42\",\"dstuser\":\"admin\"}}",
    "source": "wazuh"
  }'
```

### Example Response

```json
{
  "summary": "Multiple SSH authentication failures detected from external IP 203.0.113.42 targeting the admin account. Pattern is consistent with automated brute force activity.",
  "severity": "high",
  "alert_type": "Brute Force - SSH",
  "false_positive": {
    "score": 20,
    "label": "Investigate",
    "reasoning": "47 failures in 60 seconds from a single external IP targeting a privileged account.",
    "key_indicators": ["Multiple failures in short timeframe", "External source IP", "Targeting admin account"]
  },
  "mitre_techniques": [
    {
      "technique_id": "T1110.001",
      "technique_name": "Brute Force: Password Guessing",
      "tactic": "Credential Access",
      "confidence": 0.95,
      "url": "https://attack.mitre.org/techniques/T1110/001/"
    }
  ],
  "investigation_steps": [
    {
      "step_number": 1,
      "action": "Block source IP 203.0.113.42 at perimeter firewall",
      "priority": "immediate",
      "rationale": "Stop the active attack immediately"
    }
  ],
  "iocs": ["203.0.113.42"],
  "affected_assets": ["web-server-01", "10.0.0.50"]
}
```

---

## Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Backend | Python + FastAPI | Fast, async, auto-docs |
| AI | Groq + LLaMA 3.3 70B | Free, sub-2s inference |
| Prompts | Custom SOC-tuned templates | Built from real analyst experience |
| Frontend | Vanilla JS + CSS | Zero dependencies, instant load |
| Validation | Pydantic v2 | Type-safe request/response |
| Tests | pytest | Mocked for CI without API costs |

---

## Roadmap

- [x] Full alert analysis (explain + score + MITRE + steps)
- [x] Multi-SIEM source support
- [x] False positive scoring with evidence
- [x] IOC extraction
- [ ] Wazuh live webhook integration
- [ ] Alert history & search
- [ ] PDF incident report export
- [ ] VirusTotal / AbuseIPDB enrichment
- [ ] Slack / Teams notification integration
- [ ] Multi-tenant SaaS deployment

---

## About

Built by **Avash Shrestha** — SOC Analyst deployed at NCSC Nepal (National Cyber Security Center), Singha Durbar.

This tool was born from real frustration triaging hundreds of alerts per shift at national infrastructure level. Every design decision was made by someone who has used Splunk, FortiSIEM, and Wazuh in production.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-avashshrestha43-0077B5?style=flat&logo=linkedin)](https://linkedin.com/in/avashshrestha43)
[![GitHub](https://img.shields.io/badge/GitHub-aavashcsit-181717?style=flat&logo=github)](https://github.com/aavashcsit)

---

> ⚠️ SOCratic is intended for use in authorized security operations environments only. All analysis is AI-generated and should be validated by a qualified analyst.

## License

MIT — free to use, fork, and build on.
