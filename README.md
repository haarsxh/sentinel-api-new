# SentinelAPI — Zero-Trust API Vulnerability Scanner

> "Find the API vulnerability before the breach headline does."

[![CI](https://github.com/haarsxh/sentinel-api-new/actions/workflows/ci.yml/badge.svg)](https://github.com/haarsxh/sentinel-api-new/actions/workflows/ci.yml)
[![Publish dashboard](https://github.com/haarsxh/sentinel-api-new/actions/workflows/pages.yml/badge.svg)](https://haarsxh.github.io/sentinel-api-new/)

SentinelAPI ingests an API's **OpenAPI spec**, exercises it as several authenticated
identities, and produces **severity-ranked, verified findings** with copy-pasteable
proof-of-concept requests — plus a dashboard that engineers and non-specialists can both act on.

**Live dashboard (rebuilt nightly by CI):** https://haarsxh.github.io/sentinel-api-new/

Built for **AmiHacks Track C (Industry / Deep-Tech)**.

---

## The idea: two engines, one verifier

Template-based scanners are fast but noisy: they see `200 OK` and call it a vulnerability,
even when a user is just reading their *own* profile. A scanner that cries wolf gets ignored.

SentinelAPI runs two engines and trusts neither blindly:

| Engine | What it does |
|---|---|
| **Native** | SentinelAPI's own checks. Ownership-aware: it knows which identity owns which object, so every hit is a reproduced cross-user access, not a guess. |
| **Hadrian** *(optional)* | [Hadrian](https://github.com/praetorian-inc/hadrian)'s OWASP API Top 10 templates, run as an external binary. Broad coverage — including classes the native engine doesn't test. |

Every Hadrian alert then goes through the **verifier** (`scanner/lib/verify.js`), which
groups duplicate role-pair alerts and re-tests each one with a class-specific check:

| Class | Verification |
|---|---|
| BOLA / IDOR | Replay as the attacker against objects *owned by other identities* |
| Function-level auth (BFLA) | Compare what the low-privilege and high-privilege identities receive |
| Excessive data exposure | Parse the response and look for real sensitive fields/values |
| Missing authentication | Replay with no credentials |
| Debug info disclosure | Match stack traces / internal paths in error responses |
| HTTP verb tampering | Replay undocumented methods (sandbox only) |

Each alert ends up **confirmed** (reported with a PoC), **unverified** (reported, labelled),
**false positive** (filtered, with the reason), or **merged** into a native finding — which
is then marked *found by both engines*.

On the bundled sandbox: **Hadrian's 30 raw alerts → 11 distinct issues → 3 confirmed,
2 corroborating native findings, 8 disproved** — including false alarms on the two
deliberately secure endpoints — and one class (stack-trace disclosure) that the native engine
alone would have missed.

## Quick start

```bash
npm install

# optional: enable the Hadrian engine (needs Go 1.26+)
npm run setup:hadrian

# 1. start the bundled, intentionally vulnerable sandbox
npm run demo            # http://127.0.0.1:4000

# 2. scan it (uses Hadrian automatically when installed)
npm run scan:demo       # writes report/data/latest.json

# 3. open the dashboard
npm run report          # http://127.0.0.1:4100
```

Self-test (also runs in CI):

```bash
npm test
```

### Engine selection

```bash
node scanner/cli.js --config scanner/targets/demo.json --engine auto     # default: both if Hadrian is installed
node scanner/cli.js --config scanner/targets/demo.json --engine native   # native checks only
node scanner/cli.js --config scanner/targets/demo.json --engine all      # both; fail if Hadrian is missing
```

## What it detects

| Class | OWASP API 2023 | Native | Hadrian (verified) |
|---|---|:-:|:-:|
| Broken object-level authorization (IDOR) | API1 | ✓ | ✓ |
| Broken authentication / missing auth | API2 | ✓ | ✓ |
| Excessive data exposure | API3 | ✓ | ✓ |
| Missing rate limiting on login | API4 | ✓ | |
| Broken function-level authorization | API5 | | ✓ |
| HTTP verb tampering | API5 | | ✓ |
| Debug information disclosure | API8 | | ✓ |

## CI/CD

| Workflow | When | What |
|---|---|---|
| `ci.yml` | every push / PR | self-test with the native engine, self-test with Hadrian required, example deploy gate |
| `pages.yml` | push to `main`, nightly, manual | scans the sandbox with both engines and publishes the dashboard + findings history to GitHub Pages |
| Dependabot | weekly | keeps npm packages and GitHub Actions up to date |

The scanner exits with code `2` when any finding meets `--fail-on` (default `high`),
so it can block a deploy:

```bash
node scanner/cli.js --config scanner/targets/<your>.json --fail-on high
```

## Safety (critical)

- SentinelAPI **only runs against loopback targets by default**. Any other host requires an
  explicit `"authorization": "I am authorized to test this target"` in the target config.
- State-changing Hadrian templates and verb replays run **only against loopback sandboxes**
  unless `hadrian.allowDestructive` is set.
- Credentials handed to Hadrian live in a private temp directory (`0700`/`0600`) that is
  deleted after the run. PoC commands redact bearer tokens.
- The login burst is hard-capped, and Hadrian is rate-limited, so scans can't degrade the target.

Only test APIs you own or are explicitly authorized to test.

## Scanning your own API

Copy `scanner/targets/demo.json`, point `specPath` and `baseUrl` at your API, and list
test identities (credentials or tokens) with a privilege `level` (e.g. user `10`, admin `100`).
Add known object ids per identity under `seededObjectIds` so BOLA can be tested precisely:

```json
"seededObjectIds": { "/orders/{id}": { "alice": [1001], "bob": [2001] } }
```

Optional Hadrian settings: `hadrian.rateLimit`, `hadrian.templates`, `hadrian.allowDestructive`,
`hadrian.bin`, `hadrian.templateDir`.

## Layout

```
demo-api/          intentionally vulnerable sandbox target + its OpenAPI spec
scanner/checks/    native checks
scanner/engines/   external engine adapters (Hadrian)
scanner/lib/       spec, auth, http, verifier, merge, report, safety
report/            static findings dashboard
scripts/           Hadrian setup, findings-history builder
.github/           CI, Pages deploy, Dependabot
```

## Acknowledgements

The optional second engine is [Hadrian](https://github.com/praetorian-inc/hadrian) by
Praetorian (Apache-2.0). SentinelAPI does not vendor Hadrian's code or templates;
`scripts/setup-hadrian.sh` installs a pinned release locally.
