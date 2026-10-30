# VulnTrack Lite: Threat Model

Scope: `main` branch (v1.0). Status: ✅ implemented · ⚠️ partial / documented gap · 🔲 planned.

## 1. Intended use and assumptions

VulnTrack Lite is a **single-user, local** dashboard (FastAPI + SQLite + a vanilla-JS page). It has **no authentication or authorization by design**. It must run on `127.0.0.1` for one trusted operator. **Do not expose it to a network or the internet in its current form.** Every threat below is assessed under that assumption. v1.0 adds optional token auth and refuses non-local binds without it, but it is still not a hardened multi-user service.

## 2. Assets

CVE records (`vulnerabilities` table in `vulntrack.db`) and the integrity of the severity/score data an operator relies on for triage.

## 3. Surface

| Route | Method | Notes |
|---|---|---|
| `/`, `/static/*` | GET | Dashboard shell and vendored assets (public even when a token is set) |
| `/api/vulnerabilities` | GET / POST / DELETE | List with filters, create, clear (needs confirm header) |
| `/api/vulnerabilities/{cve}` | GET / DELETE | One record |
| `/api/vulnerabilities/import` | POST | Outbound NVD fetch, then KEV/EPSS |
| `/api/enrich` | POST | Outbound KEV + EPSS refresh |

Outbound: `services.nvd.nist.gov`, `www.cisa.gov`, `api.first.org` only.

## 4. Controls and status

| Threat | Control | Status | Evidence |
|---|---|---|---|
| SQL injection | `?` placeholders everywhere; migration DDL is static constants; severity filter allowlisted | ✅ | `main.py`, `test_sqli_and_xss_payloads_are_inert` |
| Malformed input | Pydantic: CVE regex, length limits, `extra="forbid"`, score 0-10, vector parsed strictly | ✅ | `VulnerabilityCreate`, `tests/test_cvss.py` |
| Severity/score inconsistency | Severity derived server-side; v3.x score computed from vector; mismatched client values rejected; legacy rows repaired by migration | ✅ | `cvss.py`, `init_db()` |
| Stored XSS (incl. data from NVD) | UI builds DOM with `textContent` only; no `innerHTML`; no inline handlers; CSP `script-src 'self'` | ✅ | `static/app.js`, `tests/test_frontend.py` |
| Third-party script/style/font integrity | Lucide, Inter and compiled Tailwind are vendored and pinned; no CDN requests; CSP has no `unsafe-inline` | ✅ | `static/vendor`, `static/fonts` |
| Cross-site request forgery (e.g. clear-all) | Writes need `X-Requested-With: VulnTrack` (forces a CORS preflight, which is never granted) plus same-origin `Origin` check; `/api/clear` removed; `DELETE /api/vulnerabilities` also needs `X-Confirm-Clear` | ✅ | `security_gate`, `RequestGate` tests |
| DNS rebinding against localhost | `Host` header allowlist (127.0.0.1, localhost, ::1, plus `VULNTRACK_ALLOWED_HOSTS`) | ✅ | `test_dns_rebinding_host_rejected` |
| Unauthenticated network exposure | Launcher refuses non-local bind without `VULNTRACK_TOKEN` (>= 16 chars) and allowed hosts; bearer token compared in constant time | ⚠️ | Bypassable by running `uvicorn` directly; no TLS |
| Information leakage | Global handler returns generic 500; details logged server-side; feed errors are sanitized | ✅ | `test_errors_do_not_leak_internals` |
| SSRF via feed clients | Fixed URLs, https only, host allowlist, redirects refused, CVE ID validated before use, size cap and timeout | ✅ | `feeds._http_get_json`, `FeedParsing` tests |
| Untrusted feed data | Strict parsing; vector re-validated; description truncated to 1000 chars; EPSS/KEV values type-coerced | ✅ | `feeds.parse_nvd` |
| Abuse / flooding | 120 writes/min and 10 feed calls/min per client IP; 64 KB body cap | ⚠️ | In-memory and per IP, so weak behind a shared proxy |
| Token storage in browser | Token kept in `sessionStorage` only, sent as `Authorization` header | ⚠️ | Readable by any script on the origin; mitigated by the CSP |
| CVSS v4.0 correctness | Vectors validated; score not computed locally | ⚠️ | Score must come from NVD or the operator |
| Feed availability / staleness | Enrichment failures never block import; KEV flag is not cleared when the KEV fetch fails | ✅ | `test_enrich_all_reports_warnings_and_keeps_kev_on_outage` |

## 5. If exposed beyond localhost

Set `VULNTRACK_TOKEN`, `VULNTRACK_ALLOWED_HOSTS`, and terminate TLS in a reverse proxy. Without TLS the bearer token travels in cleartext. Per-IP rate limits will see only the proxy address unless you add proxy-aware handling.

## 6. Roadmap

1. Compute CVSS v4.0 base scores locally (macrovector lookup).
2. Scheduled enrichment and a KEV-added alert.
3. Proxy-aware rate limiting; optional TLS termination.
4. Export (CSV/SARIF) and per-asset tagging.
