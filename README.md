# API Security Scanner Dashboard

An automated API endpoint crawler and security testing tool with a real-time web dashboard.

## Features

- **API Crawler**: Discovers endpoints via OpenAPI/Swagger detection, common path brute-force, HTML link extraction, and response header analysis
- **Security Tests**: Automated testing for SQL Injection, XSS, Authentication issues, CORS misconfiguration, missing security headers, and rate limiting
- **Dashboard**: Real-time React dashboard with severity charts, endpoint tables, and expandable vulnerability findings

## Quick Start

### Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

The API server starts at **http://localhost:8000**.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The dashboard opens at **http://localhost:5173**.

## Usage

1. Open the dashboard at http://localhost:5173
2. Enter a target base URL (e.g. `https://example.com`)
3. Click **Start Scan**
4. View discovered endpoints and vulnerability findings in real-time

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scan` | Start a new scan |
| GET | `/api/scans` | List all scans |
| GET | `/api/scan/{id}` | Get scan details |
| GET | `/api/scan/{id}/endpoints` | Get discovered endpoints |
| GET | `/api/scan/{id}/findings` | Get vulnerability findings |

## Security Tests

| Test | What it checks |
|------|---------------|
| SQL Injection | Error-based and boolean-based SQLi via query params and body |
| XSS | Reflected cross-site scripting via input reflection detection |
| Authentication | Unauthenticated access, invalid tokens, IDOR patterns |
| CORS | Origin reflection, wildcard with credentials, null origin |
| Security Headers | Missing HSTS, CSP, X-Frame-Options, etc. |
| Rate Limiting | Burst request testing on sensitive endpoints |

## Tech Stack

- **Backend**: Python, FastAPI, SQLAlchemy, httpx
- **Frontend**: React, Vite, Tailwind CSS, Recharts
- **Database**: SQLite

## Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper authorization before scanning any target.
