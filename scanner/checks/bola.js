// Check: Broken Object-Level Authorization (BOLA / IDOR).
//
// Method: for each secured endpoint with an object id in the path, take an id that
// belongs to identity A and request it while authenticated as identity B. If B gets
// a 2xx with a body, the endpoint is not enforcing per-object ownership.

import { toCurl } from "../lib/poc.js";

export const id = "bola";
export const title = "Broken Object-Level Authorization (IDOR)";

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

    for (const owner of sessions) {
      const ownedIds = ownership[owner.label] || [];
      for (const attacker of sessions) {
        if (attacker.label === owner.label) continue;

        for (const objId of ownedIds) {
          const path = op.path.replace(`{${param.name}}`, encodeURIComponent(objId));
          const res = await request({ method: "GET", path, headers: attacker.headers });

          if (res.status >= 200 && res.status < 300 && res.json) {
            // Confidence boost if the returned object plainly belongs to the owner.
            const body = JSON.stringify(res.json);
            const looksOwned = /"ownerId"\s*:/.test(body) || body.length > 2;

            findings.push({
              checkId: id,
              title,
              severity: "CRITICAL",
              confidence: looksOwned ? 0.95 : 0.8,
              endpoint: `${op.method} ${op.path}`,
              summary: `Identity "${attacker.label}" read object ${objId} owned by "${owner.label}" (HTTP ${res.status}).`,
              detail:
                `The endpoint returned another user's object without an ownership check. ` +
                `A request that is syntactically valid still exposed data belonging to a different user.`,
              evidence: { attacker: attacker.label, owner: owner.label, objectId: objId, status: res.status, response: res.json },
              remediation:
                "Enforce object-level authorization server-side: verify the authenticated principal owns (or is permitted to access) the requested object before returning it.",
              poc: toCurl({ ...res.request, headers: attacker.headers }),
            });
          }
        }
      }
    }
  }
  return findings;
}
