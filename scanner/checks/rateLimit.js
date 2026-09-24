// Check: Missing rate limiting on the authentication endpoint.
//
// Method: send a controlled burst of failed logins and see whether the target ever
// pushes back (HTTP 429 or a Retry-After). Absence of throttling enables credential
// stuffing / brute force.
//
// Deliberately bounded (small burst, sequential) so the check cannot degrade the target.

import { toCurl } from "../lib/poc.js";

export const id = "rate-limit";
export const title = "Missing Rate Limiting (Authentication)";

export async function run(ctx) {
  const { config, request } = ctx;
  const auth = config.auth || {};
  if (!auth.loginPath) return [];

  const burst = Math.min(config.rateLimit?.burst ?? 12, 25); // hard cap keeps this gentle
  let throttled = false;
  let lastRes;

  for (let i = 0; i < burst; i++) {
    lastRes = await request({
      method: "POST",
      path: auth.loginPath,
      body: { username: "does-not-exist", password: `wrong-${i}` },
    });
    if (lastRes.status === 429 || lastRes.status === 503) {
      throttled = true;
      break;
    }
  }

  if (throttled) return [];

  return [
    {
      checkId: id,
      title,
      severity: "MEDIUM",
      confidence: 0.75,
      endpoint: `POST ${auth.loginPath}`,
      summary: `Sent ${burst} rapid failed logins with no throttling response (no 429/503).`,
      detail: "The authentication endpoint accepted a burst of failed attempts without rate limiting, enabling brute-force and credential-stuffing attacks.",
      evidence: { attempts: burst, lastStatus: lastRes?.status },
      remediation: "Add per-IP and per-account rate limiting with exponential backoff and account lockout thresholds on authentication endpoints.",
      poc: toCurl(lastRes?.request),
    },
  ];
}
