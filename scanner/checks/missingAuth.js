// Check: Missing / broken authentication.
//
// Method: call endpoints the spec marks as secured WITHOUT any credentials.
// A 2xx means the auth requirement is not actually enforced.

import { isSecured } from "../lib/spec.js";
import { toCurl } from "../lib/poc.js";

export const id = "missing-auth";
export const title = "Missing Authentication Enforcement";

export async function run(ctx) {
  const { config, ops, request } = ctx;
  const findings = [];
  const seeded = config.seededObjectIds || {};

  for (const op of ops) {
    if (op.method !== "GET") continue;
    if (!isSecured(op)) continue; // only endpoints that claim to require auth

    let path = op.path;
    const pathParams = (op.parameters || []).filter((p) => p.in === "path");
    if (pathParams.length) {
      const sample = Object.values(seeded[op.path] || {})[0]?.[0];
      if (sample === undefined) continue;
      path = path.replace(`{${pathParams[0].name}}`, encodeURIComponent(sample));
    }

    const res = await request({ method: "GET", path, headers: {} }); // no auth header
    if (res.status >= 200 && res.status < 300) {
      findings.push({
        checkId: id,
        title,
        severity: "HIGH",
        confidence: 0.9,
        endpoint: `${op.method} ${op.path}`,
        summary: `Endpoint declared as secured returned HTTP ${res.status} with no credentials.`,
        detail: "The OpenAPI spec marks this operation as requiring authentication, but the server served it to an anonymous caller.",
        evidence: { status: res.status, response: res.json ?? res.text?.slice(0, 300) },
        remediation: "Apply the authentication middleware to this route and fail closed (401) when no valid principal is present.",
        poc: toCurl(res.request),
      });
    }
  }
  return findings;
}
