// Check: Broken Object-Level Authorization (BOLA / IDOR).
//
// Method: for each secured endpoint with an object id in the path, take an id that
// belongs to identity A and request it while authenticated as identity B. If B gets
// a 2xx with a body, the endpoint is not enforcing per-object ownership.

import { toCurl } from "../lib/poc.js";

export const id = "bola";
export const title = "Broken Object-Level Authorization (IDOR)";
export const owasp = "API1:2023";
export const verification = "cross-identity replay with known ownership";

export async function run(ctx) {
  const { config, ops, sessions, request } = ctx;
  const findings = [];
  const seeded = config.seededObjectIds || {};

  const pathParamOps = ops.filter(
    (op) => op.method === "GET" && (op.parameters || []).some((p) => p.in === "path")
  );

  for (const op of pathParamOps) {
    const ownership = seeded[op.path];
    if (!ownership) continue; // need known ownership to test cross-access precisely

    const param = op.parameters.find((p) => p.in === "path");
    const leaks = []; // every cross-identity read on this endpoint, grouped into one finding

    for (const owner of sessions) {
      const ownedIds = ownership[owner.label] || [];
      for (const attacker of sessions) {
        if (attacker.label === owner.label) continue;
        // More-privileged identities (e.g. admin) may legitimately read others' objects.
        if (attacker.level > owner.level) continue;

        for (const objId of ownedIds) {
          const path = op.path.replace(`{${param.name}}`, encodeURIComponent(objId));
          const res = await request({ method: "GET", path, headers: attacker.headers });
          if (res.status >= 200 && res.status < 300 && res.json) leaks.push({ attacker, owner, objId, res });
        }
      }
    }
    if (!leaks.length) continue;

    const first = leaks[0];
    const pairs = [...new Set(leaks.map((l) => `${l.attacker.label}→${l.owner.label}`))];
    findings.push({
      checkId: id,
      title,
      severity: "CRITICAL",
      // Confidence rises when the returned object plainly carries an owner field.
      confidence: /"ownerId"\s*:/.test(JSON.stringify(first.res.json)) ? 0.95 : 0.8,
      endpoint: `${op.method} ${op.path}`,
      summary: `${leaks.length} cross-identity read(s) succeeded (${pairs.join(", ")}), e.g. "${first.attacker.label}" read object ${first.objId} owned by "${first.owner.label}".`,
      detail:
        `The endpoint returned other users' objects without an ownership check. ` +
        `A request that is syntactically valid still exposed data belonging to a different user.`,
      evidence: {
        crossAccess: leaks.map((l) => ({ attacker: l.attacker.label, owner: l.owner.label, objectId: l.objId, status: l.res.status })),
        sampleResponse: first.res.json,
      },
      remediation:
        "Enforce object-level authorization server-side: verify the authenticated principal owns (or is permitted to access) the requested object before returning it.",
      poc: toCurl({ ...first.res.request, headers: first.attacker.headers }),
    });
  }
  return findings;
}
