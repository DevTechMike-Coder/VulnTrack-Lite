# VulnTrack Lite: Threat Model

Scope: `main` branch. Status: ✅ implemented · ⚠️ partial / documented gap · 🔲 planned.

## 1. Intended use and assumptions

VulnTrack Lite is a **single-user, local** dashboard (FastAPI + SQLite + a vanilla-JS page). It has **no authentication or authorization by design**. It must run on `127.0.0.1` for one trusted operator. **Do not expose it to a network or the internet in its current form.** Every threat below is assessed under that assumption; the "if exposed" column shows what changes.

## 2. Assets

CVE records (`vulnerabilities` table in `vulntrack.db`) and the integrity of the severity/score data an operator relies on for triage.

## 3. Surface

| Route | Method | Notes |
|---|---|---|
| `/` | GET | Serves `index.html` |
| `/api/vulnerabilities` | GET | Optional `severity` filter |
| `/api/vulnerabilities` | POST | Create a record |
| `/api/clear` | POST | Deletes every record |

## 4. Controls and status

| Threat | Control | Status | Evidence |
|---|---|---|---|
| SQL injection | All queries use `?` placeholders; the severity filter is also checked against an allowlist | ✅ | `main.py` |
| Malformed input | Pydantic: CVE id regex `^CVE-\d{4}-\d{4,7}$`, title 3–100 chars, description 10–1000, score 0.0–10.0, severity allowlist | ✅ | `VulnerabilityCreate` |
| Duplicate records | Primary key on `cve_id` plus explicit pre-check (returns 400) | ✅ | `add_vulnerability()` |
| Stored XSS in the table | Table cells and toasts pass through `escapeHtml()` (`& < > " '`); detail view uses `textContent` | ✅ | `index.html` |
| Inline-handler injection | `cve_id` is rendered into an `onclick` attribute after `escapeHtml()`; safe because the server only accepts the strict CVE pattern | ✅ | `index.html`, `main.py` |
| Severity/score inconsistency | `severity` and `score` are independent client-supplied fields; nothing checks that the score matches the severity band or derives from a CVSS vector | ⚠️ | `VulnerabilityCreate` |
| Information leakage | The POST error path returns `Database error: {str(e)}` to the client | ⚠️ | `add_vulnerability()` |
| Unauthenticated destructive action | `POST /api/clear` wipes the database with no auth and no confirmation. Because it needs no body or custom header, a malicious web page could trigger it with a cross-site form POST while the app is running locally | ⚠️ | `clear_vulnerabilities()` |
| Third-party script integrity | Tailwind CDN and `lucide@latest` are loaded from CDNs with no pinned version and no SRI; no CSP | ⚠️ | `index.html` |
| Abuse / flooding | No rate limiting | 🔲 | n/a |

## 5. If exposed beyond localhost

An unauthenticated caller can read, add, and delete all data, and any website the operator visits can wipe the database through `/api/clear`. There is also no TLS, CSP, or request throttling. These are accepted for a local tool and are not accepted for a hosted one.

## 6. Roadmap (priority order)

1. Bind to `127.0.0.1` explicitly in docs/launch command; refuse non-local binds unless an auth token is configured.
2. Replace `/api/clear` with `DELETE` that requires a confirmation token and a custom header (blocks cross-site form posts); add an allowed-origin check.
3. Compute severity from the CVSS base score (and store the vector string); validate v3.1 vs v4.0 explicitly.
4. Return generic 500 errors; log details server-side.
5. Pin CDN versions with SRI or vendor the assets; add a CSP.
6. Add NVD, CISA KEV, and EPSS enrichment; add tests for the above (injection, XSS payloads, clear-abuse).
