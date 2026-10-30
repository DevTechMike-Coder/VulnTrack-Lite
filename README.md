# VulnTrack Lite 🛡️

[![CI](https://github.com/DevTechMike-Coder/VulnTrack-Lite/actions/workflows/ci.yml/badge.svg)](https://github.com/DevTechMike-Coder/VulnTrack-Lite/actions/workflows/ci.yml)
[![CodeQL](https://github.com/DevTechMike-Coder/VulnTrack-Lite/actions/workflows/codeql.yml/badge.svg)](https://github.com/DevTechMike-Coder/VulnTrack-Lite/actions/workflows/codeql.yml)

A lightweight, single-user vulnerability tracker that answers one question: **what do I patch first?**
It combines CVSS (how bad), EPSS (how likely to be exploited) and CISA KEV (already exploited) into a triage priority.

> [!NOTE]
> **AI-Assisted Build:** This project was designed, coded, and verified by **Antigravity**, an AI coding assistant developed by Google DeepMind, in collaboration with the user. The v1.0 triage, enrichment and hardening work was reviewed against the threat model in [`docs/threat-model.md`](docs/threat-model.md).

## Features

- **Priority triage (P0-P3)** derived from CISA KEV, EPSS and CVSS (rules below).
- **NVD import:** type a CVE ID; CVSS v3.1/v4.0/v3.0 score + vector, description and dates are pulled from NVD.
- **KEV + EPSS enrichment** on import and via *Refresh intel*.
- **Derived severity:** severity is computed from the score, never trusted from the client. v3.0/v3.1 base scores are computed from the vector; v4.0 vectors are validated (see limitations).
- **Hardened by default:** localhost-only, CSRF header + origin check, Host allowlist (DNS-rebinding), strict CSP with no inline script/style and no CDNs, optional bearer token, rate limits, generic 500s.
- **Zero heavy ORMs:** stdlib `sqlite3`, FastAPI, vanilla JS.

## Triage rules

| Priority | Condition |
|---|---|
| **P0 Act now** | Listed in CISA KEV |
| **P1 Urgent** | EPSS >= 20%, or CVSS >= 9.0 with EPSS >= 5% |
| **P2 Plan** | CVSS >= 7.0 or EPSS >= 5% |
| **P3 Routine** | Everything else |

If EPSS has not been fetched yet, CVSS decides (>= 9.0 -> P1, >= 7.0 -> P2, else P3). Rules live in [`triage.py`](triage.py) and are applied at read time.

## Getting started

```bash
pip install -r requirements.txt
python main.py            # binds 127.0.0.1:8000
```

Open <http://127.0.0.1:8000>. Run the tests with `python run_tests.py`.

### Configuration (environment variables)

| Variable | Purpose |
|---|---|
| `NVD_API_KEY` | Optional NVD API key (raises the NVD rate limit) |
| `VULNTRACK_DB` | SQLite path (default `./vulntrack.db`) |
| `VULNTRACK_HOST` / `VULNTRACK_PORT` | Bind address (default `127.0.0.1:8000`) |
| `VULNTRACK_TOKEN` | Bearer token for `/api/*`. **Required (>= 16 chars)** by `python main.py` for non-local binds |
| `VULNTRACK_ALLOWED_HOSTS` | Extra allowed `Host` names, comma-separated (required for non-local binds) |

> [!WARNING]
> Running `uvicorn main:app --host 0.0.0.0` bypasses the launcher guard. This is still a single-user tool with no TLS: put it behind a TLS reverse proxy and set a token if you expose it at all.

## API

| Method | Route | Notes |
|---|---|---|
| GET | `/api/vulnerabilities` | Filters: `severity`, `priority` (0-3), `kev` |
| GET | `/api/vulnerabilities/{cve}` | One record |
| POST | `/api/vulnerabilities` | `cve_id`, `title`, `description`, and `cvss_vector` and/or `score` |
| POST | `/api/vulnerabilities/import` | `{"cve_id": "CVE-..."}` from NVD, then KEV/EPSS |
| POST | `/api/enrich` | Refresh KEV + EPSS for all records |
| DELETE | `/api/vulnerabilities/{cve}` | Delete one |
| DELETE | `/api/vulnerabilities` | Clear all; needs header `X-Confirm-Clear: delete-all` |

All non-GET requests must send `X-Requested-With: VulnTrack`. `POST /api/clear` was removed in v1.0 (it was triggerable by a cross-site form post).

## Known limitations

- **CVSS v4.0 scores are not computed locally** (that needs the macrovector lookup tables). v4.0 vectors are validated and the score must be supplied; NVD imports supply it.
- Enrichment runs only on import and on *Refresh intel*; there is no background scheduler.
- Records with only CVSS v2 data in NVD are rejected on import.
- Rate limiting is in-memory and per client IP.

## Project structure

- `main.py` - FastAPI app, DB migration, security middleware, routes
- `cvss.py` - vector parsing, v3.x calculator, severity bands
- `triage.py` - priority rules
- `feeds.py` - NVD / CISA KEV / FIRST EPSS clients (host allowlist, no redirects, size caps)
- `index.html`, `static/` - dashboard; `static/vendor` and `static/fonts` are vendored (Lucide 0.469.0, Inter)
- `tests/`, `run_tests.py` - test suite
- `docs/threat-model.md`, `SECURITY.md` - security documentation

### Rebuilding the CSS

`static/tailwind.css` is compiled and committed. After changing classes in `index.html` or `static/app.js`:

```bash
npx tailwindcss@3.4.17 -c tailwind.config.js -i static/tailwind.input.css -o static/tailwind.css --minify
```

## License

MIT. See [LICENSE](LICENSE).
