# SentinelAPI — Zero-Trust API Vulnerability Scanner

> "Find the API vulnerability before the breach headline does."

An automated scanner that ingests an API's **OpenAPI/Swagger spec**, exercises it with
multiple authenticated identities, and produces **severity-ranked, explainable findings**
with copy-pasteable proof-of-concept reproduction steps.

Built for **AmiHacks Track C (Industry / Deep-Tech)**.

---

## Why

Most teams review API security manually, infrequently, and after ship. Generic scanners
catch surface issues (headers, TLS) but miss **logic-level** flaws — the ones that cause
real breaches, like a user reading another user's `/orders/{id}`. SentinelAPI focuses on
those authorization- and data-exposure classes.

## What it detects

| Check | Class | How |
|---|---|---|
| `bola` | Broken Object-Level Authorization (IDOR) | Requests one identity's objects while authenticated as another |
| `data-exposure` | Excessive Data Exposure | Inspects responses for passwords, tokens, SSNs, card numbers |
| `missing-auth` | Missing Authentication | Calls spec-secured endpoints with no credentials |
| `rate-limit` | Missing Rate Limiting | Sends a small, bounded burst of failed logins |

Each finding includes: severity, confidence, endpoint, evidence, remediation, and a
redacted `curl` PoC.

## Safety (critical)

SentinelAPI **only runs against loopback targets by default**. To scan any non-local host
you must add an explicit authorization acknowledgment to the target config. It refuses
otherwise, fails closed, and bounds intrusive checks (e.g. the login burst is hard-capped).
Only test APIs you own or are explicitly authorized to test.

## Quick start

```bash
cd sentinel-api
npm install

# 1. start the bundled, intentionally-vulnerable sandbox target
npm run demo            # http://127.0.0.1:4000

# 2. scan it
npm run scan:demo       # writes report/data/latest.json

# 3. view findings
npm run report          # http://127.0.0.1:4100
```

Run the self-test (also runs in CI):

```bash
npm test
```

## Layout

```
demo-api/   intentionally-vulnerable sandbox target + its OpenAPI spec
scanner/    the scanner: checks/, lib/, cli.js, targets/
report/     static findings dashboard
.github/    CI pipeline (self-test + example security gate)
```

## Scanning your own API

Copy `scanner/targets/demo.json`, point `specPath` and `baseUrl` at your API, provide two
test identities (credentials or tokens), and list known object ids per identity under
`seededObjectIds` so the BOLA check can test cross-identity access precisely. Then:

```bash
node scanner/cli.js --config scanner/targets/<your>.json --fail-on high
```

Exit code is non-zero when findings meet `--fail-on`, so it can gate CI/CD.
