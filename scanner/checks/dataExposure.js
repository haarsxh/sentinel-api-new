// Check: Excessive Data Exposure.
//
// Method: call each readable endpoint as a legitimate identity and inspect the
// response body for sensitive fields the client should never receive.

import { findSensitiveFields } from "../lib/sensitive.js";
import { toCurl } from "../lib/poc.js";

export const id = "data-exposure";
export const title = "Excessive Data Exposure";
export const owasp = "API3:2023";
export const verification = "response field analysis";

export async function run(ctx) {
  const { config, ops, sessions, request } = ctx;
  const findings = [];
  const seeded = config.seededObjectIds || {};
  const session = sessions[0]; // any authenticated identity is enough to observe leakage
  if (!session) return findings;

  for (const op of ops) {
    if (op.method !== "GET") continue;

    // Resolve a concrete path (fill path params from seeded ids when present).
    let path = op.path;
    const pathParams = (op.parameters || []).filter((p) => p.in === "path");
    if (pathParams.length) {
      const ownership = seeded[op.path]?.[session.label] || Object.values(seeded[op.path] || {})[0] || [];
      const sample = ownership[0];
      if (sample === undefined) continue;
      path = path.replace(`{${pathParams[0].name}}`, encodeURIComponent(sample));
    }

    const res = await request({ method: "GET", path, headers: session.headers });
    if (!(res.status >= 200 && res.status < 300) || res.json == null) continue;

    const hits = findSensitiveFields(res.json);
    if (hits.length === 0) continue;

    // Highest-severity hit drives the finding severity.
    const order = { CRITICAL: 3, HIGH: 2, MEDIUM: 1 };
    const top = hits.reduce((a, b) => ((order[b.severity] || 0) > (order[a.severity] || 0) ? b : a));

    findings.push({
      checkId: id,
      title,
      severity: top.severity,
      confidence: 0.85,
      endpoint: `${op.method} ${op.path}`,
      summary: `Response exposes sensitive field(s): ${[...new Set(hits.map((h) => h.reason))].join(", ")}.`,
      detail: "The endpoint returns fields that clients should not receive, widening the blast radius of any leak.",
      evidence: { fields: hits, status: res.status },
      remediation:
        "Return an explicit allow-listed projection of each resource. Never serialize entire records; strip credentials, tokens, government ids and payment data at the boundary.",
      poc: toCurl({ ...res.request, headers: session.headers }),
    });
  }
  return findings;
}
