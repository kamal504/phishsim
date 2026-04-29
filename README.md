# 🎣 PhishSim — Security Awareness Platform

> A self-hosted phishing simulation and security awareness platform built from scratch.  
> Run realistic campaigns, score employee risk, auto-deliver training, and monitor live threat intelligence — all from a single dashboard.

---

## ✨ What It Does

PhishSim gives security teams a complete internal toolset to run phishing simulations, measure employee susceptibility, automatically enrol people in targeted training, and track improvement over time — without relying on any external SaaS.

---

## 🗂️ Project Structure

```
phishsim/
├── backend/                  # FastAPI application
│   ├── main.py               # App entry point, middleware, scheduler
│   ├── models.py             # SQLAlchemy ORM models
│   ├── schemas.py            # Pydantic request / response schemas
│   ├── database.py           # SQLite ↔ PostgreSQL engine config
│   ├── encryption.py         # AES-256 field-level PII encryption
│   ├── audit.py              # Tamper-proof chained audit log
│   ├── notifications.py      # Slack / webhook notification dispatch
│   ├── autonomy/
│   │   └── engine.py         # Autonomous AI campaign engine + training delivery
│   ├── risk_engine/
│   │   ├── core.py           # 3-signal risk scoring
│   │   ├── breach_monitor.py # HaveIBeenPwned / public breach checks
│   │   ├── gateway_sync.py   # Email gateway telemetry ingestion
│   │   └── gateway_adapters/ # Microsoft 365, Google Workspace, Proofpoint, Mimecast
│   ├── threat_intel/
│   │   ├── feeds.py          # OpenPhish, URLhaus, AlienVault OTX, PhishTank
│   │   └── template_generator.py  # AI-powered template generation from live IOCs
│   ├── mailbox/              # IMAP / Microsoft Graph report mailbox integration
│   ├── routers/              # All API route handlers (one file per domain)
│   └── static/
│       └── index.html        # Full single-page application (no build step)
├── frontend/                 # React + Vite (optional dev UI)
├── deploy-scripts/           # Shell scripts for VPS / DigitalOcean deployment
├── start.sh                  # macOS / Linux one-command start
├── start.bat                 # Windows one-command start
└── start.ps1                 # PowerShell start script
```

---

## 🚀 Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Python | 3.10 + |
| pip | Latest |
| Node.js | 18 + (optional — only for React dev frontend) |

### 1. Clone & Start (Linux / macOS)

```bash
git clone https://github.com/YOUR_USERNAME/phishsim.git
cd phishsim
chmod +x start.sh
./start.sh
```

### 2. Start on Windows

```bat
start.bat
```

Or with PowerShell:

```powershell
.\start.ps1
```

### 3. Open the Dashboard

```
http://localhost:8000
```

Default admin credentials are created on first boot — you will be prompted to change the password immediately.

> **API docs:** `http://localhost:8000/docs`

---

## ⚙️ Environment Variables

All variables are optional — sensible defaults are used when not set.

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./phishing_simulator.db` | Switch to PostgreSQL: `postgresql://user:pass@host:5432/phishsim` |
| `PHISHSIM_HTTPS` | `0` | Set to `1` to enforce HTTPS-only cookies and HSTS headers |
| `PHISHSIM_ORIGIN` | `http://localhost:8000` | Public base URL — used for CORS and tracking link generation |
| `PHISHSIM_DISABLE_DOCS` | _(unset)_ | Set to any value to disable `/docs` and `/redoc` in production |

---

## 🔑 Core Features

### Simulation Engine
- **Campaign builder** — custom subject, sender name, HTML body, tags, schedule, and auto-stop rules
- **A/B template testing** — split audience between two email variants; tracks open rate, click rate, and detects the winner
- **6 fake landing page themes** — Microsoft 365, HR Portal, Finance Portal, Executive Portal, Parcel Delivery, Corporate SSO
- **Live tracking dashboard** — real-time opens, clicks, credential submissions, phish reports, time-of-day heatmap, OS/browser breakdown
- **Exercise programs** — bundle campaigns into quarterly exercises with program-to-program trend comparison
- **Schedule + auto-stop** — launch at a future date/time; pause automatically when a click-rate threshold is hit
- **Send retry** — delivery health dashboard with one-click retry for failed targets

### People & Risk
- **3-signal risk engine** — scores every employee from simulation behaviour, email gateway telemetry, and breach intelligence
- **Adaptive difficulty** — high-risk employees automatically receive harder, more convincing templates on the next campaign
- **Employee directory** — CSV import; filter by department or risk band when targeting campaigns
- **Suppression list** — permanently exclude executives, legal, or anyone on leave from all simulations
- **Breach monitor** — checks employee emails against public breach databases; surfaces compromised accounts
- **Security leaderboard** — gamify awareness with department and individual rankings

### Automated Training
- **Auto-enrolment** — the moment a target clicks or submits, a training email is dispatched automatically — no admin action required
- **6 awareness modules** delivered by email with inline HTML content:
  - Phishing Basics
  - Link Inspection
  - Credential Safety
  - Password Hygiene & MFA
  - Security Awareness Foundations
  - Breach Response
- **Knowledge quiz** — 4 questions per module, 80% pass threshold, score stored on the enrolment record
- **Completion reminders** — automated follow-up for incomplete modules; completion updates the employee's risk score

### Threat Intelligence & AI
- **Live IOC feeds** refreshed every 6 hours: OpenPhish, URLhaus, AlienVault OTX, PhishTank
- **AI template generation** — LLM reads this week's threat feed and generates a phishing template that mirrors current real-world attack patterns (supports Anthropic, OpenAI, Ollama)
- **Autonomous AI engine** — proposes targeted campaigns based on risk gaps and threat intelligence; accept or reject each suggestion
- **AI campaign debrief** — LLM writes a plain-language post-campaign summary with actionable recommendations

### Operations & Compliance
- **Campaign approval workflow** — one-click approve/reject links emailed to approvers; no PhishSim login required
- **Tamper-proof audit log** — cryptographically chained record of every admin action; exportable for auditors
- **Role-based access** — Admin, Operator, and Viewer roles
- **Login brute-force lockout** — sliding-window rate limiter on auth endpoints; configurable password policy
- **PDF, CSV & Excel exports** — full campaign report with funnel analysis; per-exercise Excel bundle
- **Slack / webhook notifications** — alerts on campaign launch, click events, and risk threshold breaches
- **Report mailbox** — IMAP or Microsoft Graph integration to capture employee-reported phishing emails

---

## 🏗️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend framework | FastAPI (Python) |
| ORM | SQLAlchemy 2.0 |
| Database | SQLite (dev) · PostgreSQL (production) |
| Scheduling | APScheduler |
| PII encryption | Python `cryptography` (AES-256) |
| Authentication | bcrypt password hashing · JWT bearer tokens |
| Frontend | Single-file SPA (HTML + vanilla JS + Chart.js) |
| React UI (optional) | React 18 + Vite |
| Deployment | Uvicorn · Nginx · Docker-ready |

---

## 🌐 Deployment

### DigitalOcean / VPS (Recommended)

The `deploy-scripts/` folder contains numbered shell scripts that handle everything:

```bash
# On a fresh Ubuntu 22.04 droplet:
bash deploy-scripts/01_server_setup.sh
bash deploy-scripts/02_deploy_app.sh
bash deploy-scripts/03_configure_nginx.sh
bash deploy-scripts/04_setup_https.sh   # Certbot / Let's Encrypt
```

### Expose Locally with ngrok (Quick demo)

```bash
# Start PhishSim
./start.sh

# In a second terminal
ngrok http 8000

# Copy the https://xxxx.ngrok-free.app URL
# Paste it into Settings → Infrastructure → Public Base URL
```

### PostgreSQL (Production)

```bash
export DATABASE_URL="postgresql://phishsim:yourpassword@localhost:5432/phishsim"
./start.sh
```

Migrations run automatically on startup — existing data is preserved.

---

## 🔐 Security Notes

- All PII (email addresses, names, departments) is encrypted at rest with AES-256
- Passwords are hashed with bcrypt (cost factor 12)
- SMTP credentials and API keys are stored encrypted
- Rate limiting is applied to all authentication endpoints
- Security headers (HSTS, CSP, X-Frame-Options, etc.) are enforced via middleware
- Set `PHISHSIM_HTTPS=1` and `PHISHSIM_DISABLE_DOCS=1` before any production deployment

---

## 📊 API Reference

Interactive API documentation is available at:

```
http://localhost:8000/docs       # Swagger UI
http://localhost:8000/redoc      # ReDoc
```

Key endpoint groups:

| Prefix | Description |
|--------|-------------|
| `/api/campaigns` | Campaign CRUD, targeting, dispatch, delivery health |
| `/api/analytics` | Funnel stats, department heatmap, A/B results, exports |
| `/api/risk` | Employee risk scores, breach scanning, gateway sync |
| `/api/autonomy` | AI suggestions, training enrolments, quiz endpoints |
| `/api/threat-intel` | IOC feeds, trending threats, AI template generation |
| `/api/exercises` | Exercise programs, quarterly comparison |
| `/api/employees` | Employee directory, CSV import |
| `/api/approvals` | Approval workflow config and queue |
| `/api/auth` | Login, logout, user management |

---

## 🗺️ Roadmap

- [ ] SAML / SSO integration
- [ ] Multi-tenant / organisation support
- [ ] Mobile-responsive UI
- [ ] Native Docker Compose file
- [ ] Webhook templates (Teams, PagerDuty)
- [ ] Automated red-team scenario builder

---

## ⚠️ Disclaimer

PhishSim is built for **authorised internal security awareness programmes only**.  
Always obtain written permission from your organisation's leadership before running any phishing simulation.  
Never use this tool against individuals or organisations without explicit consent.

---

*Built from scratch — self-hosted — no external SaaS dependencies.*
