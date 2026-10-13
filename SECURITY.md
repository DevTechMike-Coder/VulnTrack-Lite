# Security Policy

This policy covers **VulnTrack Lite** (`DevTechMike-Coder/VulnTrack-Lite`). The design assumptions, controls, and known limitations are documented in [`docs/threat-model.md`](docs/threat-model.md).

## Supported versions

Only the `main` branch is supported. Fixes are not backported.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

1. Preferred: use GitHub's private reporting at
   <https://github.com/DevTechMike-Coder/VulnTrack-Lite/security/advisories/new>
   (enable *Settings → Code security → Private vulnerability reporting* on the repo if the link 404s).
2. Alternative: contact me through <https://micahkesiena.vercel.app> and say you have a security report. Do not include exploit details until we have a private channel.

Include, where possible: affected route/file, steps to reproduce, impact, and a suggested fix. A minimal proof of concept is enough; please avoid accessing, modifying, or deleting data that is not yours.

## What to expect

<!-- Edit these to commitments you can keep. -->
- Acknowledgement within **72 hours**.
- Initial assessment within **7 days**.
- Fix or mitigation plan for confirmed issues within **30 days** (sooner for critical issues).
- Credit in the release notes / advisory if you want it.

## Scope

In scope:
- Input validation and injection in the FastAPI API
- XSS in the dashboard frontend
- Logic flaws in how severity and scores are stored or displayed

Out of scope:
- The absence of authentication: this is a single-user local tool and is documented as not safe to expose publicly (see the threat model)
- Findings that require network exposure the README warns against

## Safe harbor

Good-faith research that stays within this policy, does not degrade service for others, does not exfiltrate or retain data beyond what is needed to demonstrate the issue, and gives me reasonable time to fix before disclosure will not be pursued legally by me. This applies to this repository's code and to deployments I operate; it does not authorize testing other people's deployments or third-party services.

## Disclosure

Coordinated disclosure: please wait for a fix or 90 days from the report, whichever comes first, before publishing details.
