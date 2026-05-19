# repo-sec · AI-Powered Repository Security Scanner

<p align="center">
  <strong>A production-grade security scanner that detects hardcoded secrets, vulnerable dependencies, and misconfigurations in any public GitHub repository.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.111+-009688?style=flat-square&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black" />
  <img src="https://img.shields.io/badge/Vite-5-646CFF?style=flat-square&logo=vite&logoColor=white" />
  <img src="https://img.shields.io/badge/MCP-Discoverable-00ff88?style=flat-square" />
</p>

---

## What is repo-sec?

**repo-sec** is an AI-native security microservice that scans any public GitHub repository through a 3-stage pipeline:

1. **Secrets Detection** — 30+ regex rules (inspired by [Gitleaks](https://github.com/gitleaks/gitleaks)) with Shannon entropy analysis to catch API keys, tokens, private keys, and database credentials
2. **Dependency Vulnerability Scanning** — Real-time CVE lookup via [OSV.dev](https://osv.dev/) (Google's open vulnerability database) with CVSS scores and fix versions
3. **Misconfiguration Detection** — Flags committed `.env` files, Dockerfile anti-patterns, debug mode flags, CORS wildcards, and insecure defaults

### Key Features

| Feature | Description |
|---|---|
| **Real Scanning Engine** | Actually fetches repo contents via GitHub API, not simulated data |
| **30+ Secret Patterns** | AWS, GitHub, Stripe, Slack, OpenAI, Anthropic, npm, PyPI, and more |
| **Shannon Entropy** | Reduces false positives by validating string randomness (threshold >3.5) |
| **OSV.dev Integration** | Batch API queries for real CVE data with CVSS scores and fix versions |
| **5 Manifest Parsers** | package.json, requirements.txt, go.mod, Gemfile.lock, composer.json |
| **Concurrent Downloads** | 20-connection parallel file fetching for fast scans |
| **MCP Discoverable** | `/skill.json` + `/openapi.json` for AI agent discoverability |
| **Threat Score Gauge** | Animated SVG gauge with tier-based scoring (not just raw sums) |
| **Export Reports** | One-click JSON download of full scan results |
| **Terminal UI** | Premium dark-theme dashboard with terminal-style scan progress |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    React + Vite Frontend (:8080)                │
│                                                                 │
│  ┌──────────┐  ┌──────────────┐  ┌────────────┐  ┌───────────┐│
│  │ ScanForm │  │ ScanProgress │  │ ThreatGauge│  │RecentScans││
│  └────┬─────┘  └──────────────┘  └────────────┘  └───────────┘│
│       │  POST /scan                                             │
│       ▼                                                         │
│  ┌──────────────────────────────────────────────────────────────┐
│  │                FastAPI Backend (:8000)                       │
│  │                                                              │
│  │  1. GitHub API ──► Fetch file tree (1 API call)              │
│  │  2. raw.githubusercontent.com ──► Download files (20x async) │
│  │  3. Secrets Scanner ──► 30+ regex + entropy analysis         │
│  │  4. Dependency Scanner ──► OSV.dev batch API                 │
│  │  5. Misconfig Scanner ──► .env / Dockerfile / debug checks   │
│  │  6. Fix Suggestion Engine ──► Prioritized remediation        │
│  │                                                              │
│  │  Endpoints:                                                  │
│  │    POST /scan          GET /health                           │
│  │    GET  /scans         GET /skill.json                       │
│  │    GET  /scans/{id}    GET /docs (Swagger)                   │
│  └──────────────────────────────────────────────────────────────┘
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+

### 1. Install & Run Backend

```bash
cd backend
pip install -r requirements.txt
python main.py
# Server starts on http://localhost:8000
# Swagger docs at http://localhost:8000/docs
```

### 2. Install & Run Frontend

```bash
npm install
npm run dev
# Dashboard at http://localhost:8080
```

### 3. Scan a Repository

Open `http://localhost:8080`, paste any public GitHub repo URL, and click **SCAN REPOSITORY**.

Or use the API directly:

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/juice-shop/juice-shop"}'
```

---

## API Reference

### `POST /scan`

Scan a GitHub repository for security issues.

**Request:**
```json
{
  "repo_url": "https://github.com/owner/repo"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scanId": "uuid",
    "repoName": "owner/repo",
    "severity": "CRITICAL | HIGH | MEDIUM | LOW | CLEAN",
    "findings": [
      {
        "id": "SEC-A1B2C3D4",
        "type": "SECRET | VULNERABILITY | MISCONFIGURATION",
        "severity": "CRITICAL",
        "title": "AWS Access Key ID",
        "description": "...",
        "file": "src/config.js",
        "line": 42,
        "evidence": "AKIA********************",
        "cve": "CVE-2024-..."
      }
    ],
    "fixSuggestions": [...],
    "filesScanned": 150,
    "findingsCount": 12,
    "durationMs": 15234
  }
}
```

### `GET /scans`

List recent scan results (up to 50).

### `GET /health`

Health check — returns `{"status": "ok"}`.

### `GET /skill.json`

MCP discoverability manifest for AI agent integration.

---

## Secret Detection Rules

Patterns based on publicly documented API key formats:

| Provider | Pattern Prefix | Severity |
|---|---|---|
| AWS Access Key | `AKIA`, `ASIA` | CRITICAL |
| GitHub PAT | `ghp_`, `gho_`, `ghs_` | CRITICAL |
| Stripe Secret Key | `sk_live_`, `sk_test_` | CRITICAL |
| Google API Key | `AIza` | HIGH |
| Slack Bot Token | `xoxb-` | HIGH |
| OpenAI API Key | `sk-` | HIGH |
| Anthropic API Key | `sk-ant-` | HIGH |
| npm Token | `npm_` | HIGH |
| SendGrid Key | `SG.` | HIGH |
| Private Key (PEM) | `-----BEGIN` | CRITICAL |
| Database URL | `mongodb://`, `postgres://` | CRITICAL |
| JWT | `eyJ...` | MEDIUM |
| Generic Secret | keyword + high entropy string | HIGH |

---

## Misconfig Checks

| Check | What's Flagged | Severity |
|---|---|---|
| `.env` committed | `.env`, `.env.local`, `.env.production` | CRITICAL |
| Dockerfile root | `USER root` or no USER instruction | HIGH / MEDIUM |
| Unpinned base image | `FROM node` (no version tag) | MEDIUM |
| Debug mode | `DEBUG=True`, `NODE_ENV=development` | HIGH |
| CORS wildcard | `Access-Control-Allow-Origin: *` | MEDIUM |
| npm auth token | `_authToken` in committed `.npmrc` | CRITICAL |
| SSL disabled | `verify=False` in Python configs | HIGH |

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Frontend** | React 18, Vite 5 | Dashboard UI |
| **Styling** | Vanilla CSS, JetBrains Mono | Terminal aesthetic |
| **Icons** | Lucide React | UI iconography |
| **Backend** | FastAPI, Python 3.10 | API server |
| **HTTP Client** | httpx (async) | GitHub API + OSV.dev |
| **Data** | Pydantic v2 | Schema validation |
| **Vuln DB** | OSV.dev API | CVE data (free, no key) |
| **MCP** | skill.json + OpenAPI | Agent discoverability |

---

## Project Structure

```
repo-sec/
├── backend/
│   ├── main.py                    # FastAPI app + scan orchestration
│   ├── requirements.txt           # Python dependencies
│   ├── skill.json                 # MCP manifest
│   └── scanner/
│       ├── models.py              # Pydantic response models
│       ├── github_fetcher.py      # Async GitHub API client
│       ├── secrets_scanner.py     # 30+ regex rules + entropy
│       ├── dependency_scanner.py  # 5 parsers + OSV.dev API
│       └── misconfig_scanner.py   # 10+ config checks
├── src/
│   ├── App.jsx                    # Main app layout
│   ├── styles.css                 # Full design system
│   └── components/
│       ├── ScanForm.jsx           # URL input + scan trigger
│       ├── ScanProgress.jsx       # Terminal-style progress
│       ├── ScanResults.jsx        # Tabbed findings display
│       ├── ThreatGauge.jsx        # Animated SVG gauge
│       ├── FindingCard.jsx        # Individual finding detail
│       ├── SeverityBadge.jsx      # Severity indicator
│       └── RecentScans.jsx        # Scan history
├── index.html                     # Entry point
├── vite.config.js                 # Vite + proxy config
└── package.json                   # Node dependencies
```

---

## Author

**Shubham Sharma** · Security Researcher & Full-Stack Engineer

- TON/Telegram Blockchain Contest — 2 confirmed consensus-layer DoS findings
- 40+ merged PRs across Swift Compiler, Jenkins, Screenpipe (18k★)
- Production vulnerability report via Jenkins AI Chatbot plugin

---

## License

MIT
