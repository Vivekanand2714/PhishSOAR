# PhishSOAR

Cyber Hackathon | FoSC 23CSE313 | Amrita Vishwa Vidyapeetham

A real-time email monitoring and automated threat classification system. PhishSOAR watches your inbox continuously, extracts Indicators of Compromise from every incoming email, enriches them via VirusTotal and URLScan.io threat intelligence, and classifies each email as **Malicious**, **Suspicious**, or **Clean** — with a full incident report generated in under 60 seconds.

---

## Table of Contents

1. Project Overview
2. Pipeline Architecture
3. Classification Verdicts
4. Tech Stack
5. Project Structure
6. Prerequisites
7. Installation
8. How to Run
9. How It Works
10. API Reference
11. MITRE ATT&CK Coverage
12. Limitations
13. Author

---

## 1. Project Overview

| | |
|---|---|
| Language | Python 3.x |
| Email Sources | Gmail (OAuth 2.0), Outlook (MSAL), Mock accounts |
| Threat Intel | VirusTotal API, URLScan.io API |
| AI Advisory | Local Gemma LLM via Ollama |
| Dashboard | Flask + real-time web UI |
| Database | SQLite |
| Classification | MALICIOUS / SUSPICIOUS / CLEAN |
| SLA Target | < 60 seconds per email |

PhishSOAR runs a 6-stage pipeline on every incoming email:

- Extracts IoCs — URLs, domains, attachments, header anomalies, phishing keywords
- Enriches each IoC via VirusTotal (URL + domain reputation) and URLScan.io
- Validates sender domain authenticity (SPF/DKIM-style trust checks)
- Scores the email 0–100 using a weighted decision engine
- Classifies and responds based on verdict
- Generates a JSON incident ticket and HTML report

---

## 2. Pipeline Architecture

```
Inbox (Gmail / Outlook / Mock)
         │
         ▼
[Stage 1] Email Ingestion
          Gmail OAuth 2.0 / Outlook MSAL / Mock polling
         │
         ▼
[Stage 2] IoC Extraction
          URLs, domains, IPs, attachments, header anomalies,
          phishing keywords, reply-to mismatch, lookalike domains
         │
         ▼
[Stage 3] Threat Intel Enrichment
          VirusTotal (URL + domain reputation)
          URLScan.io (URL scan + brand impersonation detection)
          Sender domain trust validation
         │
         ▼
[Stage 4] Triage Decision Engine
          Weighted score (0–100)
          Verdict: MALICIOUS / SUSPICIOUS / CLEAN
         │
         ▼
[Stage 5] Response Actions
          Quarantine email (Gmail API / Outlook Graph API)
          Block malicious IoCs → blocklist.txt
          Slack / webhook notification
         │
         ▼
[Stage 6] Report Generation
          JSON incident ticket + HTML report
          Gemma AI security advisory (local LLM via Ollama)
         │
         ▼
[Web Dashboard] Real-time pipeline visualization at localhost:5000
```

---

## 3. Classification Verdicts

| Score | Verdict | Action Taken |
|-------|---------|-------------|
| 60 – 100 | 🔴 MALICIOUS | Quarantine email + Block all IoCs + Alert |
| 30 – 59 | 🟡 SUSPICIOUS | Quarantine for analyst review + Alert |
| 0 – 29 | 🟢 CLEAN | No action |

**Scoring factors:**

| Signal | Points |
|--------|--------|
| URL flagged malicious by VirusTotal (≥3 vendors) | +40 |
| URLScan.io malicious verdict | +30 |
| Brand impersonation detected (URLScan) | +30 |
| Domain flagged malicious by VirusTotal | +35 |
| Spoofed sender domain | +45 |
| Untrusted sender domain | +30 |
| Suspicious attachment (.exe, .js, .vbs, etc.) | +25 |
| High phishing keyword density (≥5 keywords) | +20 |
| Reply-to / return-path domain mismatch | +10 |
| Suspicious TLD (.tk, .ml, .ga, .xyz, etc.) | +10 |
| Header anomaly | +5 each |

---

## 4. Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.x |
| Web Framework | Flask + Flask-CORS |
| Email — Gmail | Google API Python Client (OAuth 2.0) |
| Email — Outlook | MSAL (Microsoft Authentication Library) |
| Threat Intel | VirusTotal API v3, URLScan.io API |
| HTML Parsing | BeautifulSoup4 |
| DNS Checks | dnspython |
| AI Advisory | Gemma LLM (local, via Ollama on port 11434) |
| Database | SQLite (via db_manager.py) |
| Frontend | Vanilla JS + CSS (dark cyberpunk theme) |

---

## 5. Project Structure

```
PhishSOAR/
├── main.py               # Pipeline orchestrator — runs all 6 stages
├── server.py             # Flask REST API + dashboard server
├── email_parser.py       # IoC extraction (URLs, domains, attachments, headers)
├── threat_intel.py       # VirusTotal + URLScan.io enrichment
├── triage.py             # Scoring engine + verdict + MITRE ATT&CK mapping
├── response_actions.py   # Quarantine + IoC block + Slack notification
├── report_generator.py   # JSON ticket + HTML incident report
├── gemma_advisor.py      # Local Gemma LLM advisory generator (Ollama)
├── gmail_connector.py    # Gmail OAuth 2.0 — fetch + quarantine
├── outlook_connector.py  # Outlook MSAL — fetch + quarantine
├── cert_checker.py       # Sender domain trust validation
├── db_manager.py         # SQLite — accounts, emails, verdicts
├── config.py             # Configuration + constants
├── .env.example          # API keys template (copy to .env)
├── requirements.txt      # Python dependencies
├── blocklist.txt         # IoC blocklist (auto-updated on MALICIOUS verdict)
├── dashboard/
│   ├── index.html        # Dashboard UI
│   ├── style.css         # Dark cyberpunk theme
│   └── app.js            # Real-time polling + pipeline visualization
└── reports/              # Generated HTML reports + JSON tickets (auto-created)
```

---

## 6. Prerequisites

- Python 3.8 or higher
- pip
- VirusTotal API key — free at https://virustotal.com (optional, enables real threat intel)
- URLScan.io API key — free at https://urlscan.io (optional)
- Gmail account + Google OAuth credentials (optional, for live Gmail monitoring)
- Ollama installed locally (optional, for Gemma AI advisories)

PhishSOAR works fully in **demo mode** without any API keys.

---

## 7. Installation

```bash
# 1. Clone the repository
git clone https://github.com/Vivekanand2714/PhishSOAR.git
cd PhishSOAR

# 2. Create and activate a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys (optional)
copy .env.example .env       # Windows
# cp .env.example .env       # macOS / Linux

# Edit .env and fill in:
# VIRUSTOTAL_API_KEY=your_key_here
# URLSCAN_API_KEY=your_key_here
# SLACK_WEBHOOK_URL=your_webhook_here  (optional)
```

---

## 8. How to Run

### Start the Dashboard Server

```bash
python server.py
```

Browser opens automatically at **http://localhost:5000**

### Command Line (no dashboard)

```bash
# Demo mode — uses built-in phishing email sample (no API keys needed)
python main.py --demo

# Live Gmail mode — fetches latest unread email from inbox
python main.py

# Process a specific Gmail message by ID
python main.py --email-id <GMAIL_MESSAGE_ID>

# Skip Gmail auth (demo only)
python main.py --demo --no-gmail
```

### Dashboard Controls

| Button | Action |
|--------|--------|
| Run Demo | Runs pipeline on built-in phishing email sample |
| Live Gmail | Connects to Gmail and monitors real inbox |
| Live Outlook | Connects to Outlook and monitors real inbox |
| Monitor Both | Starts continuous multi-account polling (every 10s) |

---

## 9. How It Works

```
Startup
  └── Background monitoring daemon starts
  └── Loads all accounts from SQLite (adds mock accounts if empty)

Backfill Phase
  └── Fetches all unread emails from each account
  └── Runs full 6-stage pipeline on each email
  └── Saves verdict + ticket to SQLite

Monitoring Phase (continuous, every 10 seconds)
  └── Polls each account for new emails
  └── Runs pipeline on any new unread email
  └── Updates dashboard in real time

Per-email Pipeline
  ├── Stage 1: Parse email — subject, body, headers, attachments
  ├── Stage 2: Extract IoCs — URLs, domains, IPs, keywords, header anomalies
  ├── Stage 3: Enrich via VirusTotal + URLScan.io + sender trust check
  ├── Stage 4: Score 0–100 → MALICIOUS / SUSPICIOUS / CLEAN
  ├── Stage 5: Execute response (quarantine / block / alert)
  └── Stage 6: Generate HTML report + JSON ticket + Gemma AI advisory
```

---

## 10. API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/run | Start playbook (demo or live source) |
| GET | /api/status | Get current pipeline stage and result |
| GET | /api/accounts | List all monitored accounts |
| POST | /api/accounts/add | Add a new account (Gmail / Outlook / Mock) |
| POST | /api/accounts/delete | Remove an account |
| GET | /api/mails | List processed emails (filterable by account/folder) |
| GET | /api/mails/`<id>` | Get full email details + ticket |
| POST | /api/mails/`<id>`/read | Mark email as read |
| GET | /api/reports | List all generated incident reports |
| GET | /api/report/`<ticket_id>` | Fetch HTML incident report |
| GET | /api/ticket/`<ticket_id>` | Fetch JSON incident ticket |

Full interactive docs available at the dashboard when server is running.

---

## 11. MITRE ATT&CK Coverage

| Technique ID | Name | Coverage |
|-------------|------|---------|
| T1566 | Phishing | Detected + Classified |
| T1566.001 | Spearphishing Attachment | Detected (suspicious attachment flagging) |
| T1566.002 | Spearphishing Link | Detected + Blocked (VirusTotal + URLScan) |
| T1598 | Phishing for Information | Monitored (keyword density + lookalike domains) |

---

## 12. Limitations

- **Evasion**: Adversaries using URL shorteners, legitimate CDNs, or zero-day domains not yet in VirusTotal can bypass detection
- **Rate limits**: VirusTotal free tier = 4 requests/min — production use needs a paid tier
- **Attachment analysis**: Static metadata only (file extension + MIME type) — no dynamic sandbox; production would integrate Cuckoo or Any.run
- **Proxy block**: Writes to `blocklist.txt` (mock) — real deployment needs firewall API integration (Palo Alto, Cisco, Squid)
- **Gmail OAuth scope**: Requires `gmail.modify` permission — enterprise deployments should use service accounts

---

## 13. Author

Amrita Vishwa Vidyapeetham

Venkata Sai Vivekanand Tammana
Computer Science Engineering Student | AWS Certified Cloud Practitioner
Data Analytics, Machine Learning & NLP Enthusiast

[GitHub](https://github.com/Vivekanand2714)
