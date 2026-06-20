# InjectSurge

> SQL + NoSQL Injection Surface Scanner for authorized penetration testing.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-2.0-orange)

---

## What It Does

InjectSurge crawls HTML forms on a target page, fingerprints the backend database from response headers and error strings, then fires targeted injection payloads — both SQL and NoSQL — and evaluates each response for real signs of vulnerability: status code changes, response length shifts, time delays, and new session cookies.

Built for professional VAPT engagements where you need accurate, explainable findings you can put directly in a report.

---

## Features

- **Auto DB fingerprinting** — detects MySQL, MSSQL, Oracle, PostgreSQL, SQLite, MongoDB, CouchDB from response headers and error strings
- **Auto body-mode detection** — probes whether the target expects `application/json` or `application/x-www-form-urlencoded`, tries both if ambiguous
- **Real NoSQL operator payloads** — sends `{"$ne": "x"}` as actual nested JSON objects, not stringified form values (the common mistake that makes most scanners miss NoSQL injection entirely)
- **Combined-field testing** — applies the same operator to all fields simultaneously, catching auth bypasses that only trigger when every field carries the payload (e.g. `{username: {$ne: null}, password: {$ne: null}}`)
- **Multi-signal detection** — status code changes, response length delta, new cookies, time delays, DB error strings
- **Polite delay** between requests, configurable
- **SSL verification toggle**, custom cookies and headers support

---

## Supported Databases

| Database   | Error-based | Time-based | Auth bypass | NoSQL operators |
|------------|-------------|------------|-------------|-----------------|
| MySQL      | ✅          | ✅         | ✅          | —               |
| MSSQL      | ✅          | ✅         | ✅          | —               |
| Oracle     | ✅          | —          | ✅          | —               |
| PostgreSQL | ✅          | ✅         | ✅          | —               |
| SQLite     | ✅          | —          | ✅          | —               |
| MongoDB    | ✅          | —          | ✅          | ✅              |
| CouchDB    | —           | —          | ✅          | ✅              |

---

## Installation

```bash
git clone https://github.com/sherazkazmi613/InjectSurge.git
cd InjectSurge
pip install -r requirements.txt
```

**requirements.txt**
```
requests
beautifulsoup4
colorama
```

---

## Usage

**Basic scan:**
```bash
python3 inject_scanner.py https://target.com/login
```

**With authentication cookies:**
```bash
python3 inject_scanner.py https://target.com/login \
  --cookies "session=abc123; csrf=xyz"
```

**Force JSON mode (for REST/API endpoints):**
```bash
python3 inject_scanner.py https://target.com/api/login \
  --mode json
```

**Force form mode:**
```bash
python3 inject_scanner.py https://target.com/login \
  --mode form
```

**With custom headers and slower delay:**
```bash
python3 inject_scanner.py https://target.com/login \
  --headers '{"X-Forwarded-For": "127.0.0.1"}' \
  --delay 1.0
```

**Skip SSL verification (self-signed certs):**
```bash
python3 inject_scanner.py https://target.com/login --no-verify
```

---

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `url` | required | Target URL pointing to the page containing the form |
| `--mode` | `auto` | Body encoding: `auto`, `json`, or `form` |
| `--cookies` | — | Cookie string: `"name=val; name2=val2"` |
| `--headers` | — | Extra headers as JSON string |
| `--delay` | `0.3` | Seconds between requests |
| `--timeout` | `10` | Request timeout in seconds |
| `--no-verify` | off | Disable SSL certificate verification |

---

## Output Guide

```
[*]     info — normal progress
[+]     clean — payload tested, no indicator found
[!]     warning — anomaly worth manual review
[VULN]  confirmed — real indicator detected
[-]     error — request failed
```

**Confirmed finding example:**
```
[VULN]   [MSSQL/form] Auth bypass (field: txtBatchNo)
[VULN]        payload   : ' OR 1=1--
[VULN]        indicator : status changed 500 -> 200 (auth likely bypassed)
[VULN]        status=200  len=3393  time=0.09s
```

---

## How Detection Works

InjectSurge uses five independent signals, checked in order:

1. **Time delay** — response takes ≥2.5s on a time-based payload (SLEEP, WAITFOR)
2. **DB error strings** — known error substrings from MySQL, MSSQL, Oracle, PostgreSQL, SQLite, MongoDB in the response body
3. **Status code change** — baseline was 4xx, payload response is 2xx (auth bypass pattern)
4. **New session cookie** — `Set-Cookie` header appears where baseline had none
5. **Response length increase** — body grew >300 chars and >15% vs baseline

---

## File Structure

```
InjectSurge/
├── inject_scanner.py     # main scanner
├── requirements.txt
└── README.md
```

---

## Important: Legal & Ethical Use

**InjectSurge is for authorized security testing only.**

Only run this tool against systems you own, or systems where you have explicit written authorization from the owner (signed VAPT agreement, bug bounty scope, or equivalent). Unauthorized use is illegal in most jurisdictions — in Pakistan specifically, it falls under PECA 2016 Section 3 and Section 4.

The tool prints an authorization reminder on every run. That reminder is there for a reason.

---

## Author

**Sheraz** — [Codethus](https://codethus.com) | CEH | ISO/IEC 27001  
Lahore-based cybersecurity agency specializing in VAPT, red team exercises, and SOC/SIEM services.

---

## License

MIT — free to use, modify, and distribute. Attribution appreciated.
