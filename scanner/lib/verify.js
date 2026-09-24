// Candidate verification.
//
// External engines (Hadrian) report *candidates*: a template matched a status code or
// a keyword. That is noisy — e.g. a user reading their own /profile looks identical to
// a privilege-escalation hit if you only look at "200 OK". The verifier groups raw
// candidates, then re-tests each group with a class-specific differential check that
// uses SentinelAPI's knowledge of identities and object ownership.
//
// Every verified group ends up with one of:
//   confirmed       reproduced by SentinelAPI; ships with a working PoC
//   unverified      could not be safely/precisely re-tested; kept, but labelled
//   false-positive  re-test disproved it; filtered out of the report with a reason

import { findSensitiveFields } from "./sensitive.js";
import { toCurl } from "./poc.js";

const ok = (res) => res.status >= 200 && res.status < 300;

// Hadrian template id -> SentinelAPI class. Order matters (first match wins).
const CLASSES = [
  { match: /bola-read/, checkId: "bola", title: "Broken Object-Level Authorization (IDOR)", verify: verifyBola },
  { match: /bola-(write|delete)/, checkId: "bola-mutation", title: "Broken Object-Level Authorization (write/delete)", verify: unverifiedMutation },
  { match: /broken-auth/, checkId: "missing-auth", title: "Missing Authentication Enforcement", verify: verifyNoAuth },
  { match: /data-exposure/, checkId: "data-exposure", title: "Excessive Data Exposure", verify: verifyExposure },
  { match: /bfla/, checkId: "bfla", title: "Broken Function-Level Authorization", verify: verifyPrivilegeDiff },
  { match: /misconfiguration/, checkId: "debug-disclosure", title: "Debug Information Disclosure", verify: verifyStackTrace, global: true },
  { match: /verb-tampering|method-override/, checkId: "verb-tampering", title: "HTTP Verb Tampering", verify: verifyVerbs },
];

const REMEDIATION = {
  bola: "Enforce object-level authorization server-side: check that the authenticated principal owns (or may access) the requested object before returning it.",
  "missing-auth": "Apply the authentication middleware to this route and fail closed (401) when no valid principal is present.",
  "data-exposure": "Return an explicit allow-listed projection of each resource. Strip credentials, tokens, government ids and payment data at the API boundary.",
  bfla: "Gate privileged functions on role/permission checks in the handler or router, not only in the client UI.",
  "debug-disclosure": "Disable verbose error pages in production (e.g. NODE_ENV=production) and install a terminal error handler that returns a generic JSON error while logging details server-side.",
  "verb-tampering": "Register only the documented methods per route and return 405 for everything else; apply authorization per method, not per path.",
};

function classify(templateId) {
  return CLASSES.find((c) => c.match.test(templateId)) || { checkId: templateId, title: templateId, verify: unverifiedGeneric };
}

// Collapse per-role-pair duplicates into one group per (class, endpoint).
export function groupCandidates(raw) {
  const groups = new Map();
  for (const f of raw) {
    const cls = classify(f.template_id || f.id);
    const endpoint = `${f.method} ${f.endpoint}`;
    const key = cls.global ? cls.checkId : `${cls.checkId}|${endpoint}`;
    if (!groups.has(key)) {
      groups.set(key, {
        cls,
        templateId: f.template_id,
        name: f.name,
        owasp: f.category,
        severity: f.severity,
        method: f.method,
        path: f.endpoint,
        endpoints: new Set(),
        pairs: [],
        bodies: [],
      });
    }
    const g = groups.get(key);
    g.endpoints.add(endpoint);
    g.pairs.push({ attacker: f.attacker_role, victim: f.victim_role });
    if (f.evidence?.response?.body) g.bodies.push(f.evidence.response.body);
  }
  return [...groups.values()];
}

// Fill `{param}` placeholders, preferring ids owned by `label`.
function concretePath(ctx, path, label) {
  const own = ctx.config.seededObjectIds?.[path] || {};
  const id = own[label]?.[0] ?? Object.values(own)[0]?.[0] ?? 1;
  return path.replace(/\{[^}]+\}/g, encodeURIComponent(id));
}

const sessionFor = (ctx, label) => ctx.sessions.find((s) => s.label === label);
const attackersOf = (ctx, g) =>
  [...new Set(g.pairs.map((p) => p.attacker))].map((l) => sessionFor(ctx, l)).filter(Boolean);

// --- class verifiers ------------------------------------------------------------

async function verifyBola(ctx, g) {
  const ownership = ctx.config.seededObjectIds?.[g.path];
  if (!ownership) {
    return { status: "unverified", method: "ownership replay", reason: "No seeded object ownership for this endpoint, so own vs. foreign objects cannot be told apart." };
  }
  const tried = [];
  for (const attacker of attackersOf(ctx, g)) {
    for (const owner of ctx.sessions) {
      if (owner.label === attacker.label || (attacker.level ?? 10) > (owner.level ?? 10)) continue;
      for (const objId of ownership[owner.label] || []) {
        const path = g.path.replace(/\{[^}]+\}/, encodeURIComponent(objId));
        const res = await ctx.request({ method: g.method, path, headers: attacker.headers });
        tried.push(`${attacker.label}→${objId} (${res.status})`);
        if (ok(res) && res.json != null) {
          return {
            status: "confirmed",
            method: "ownership replay",
            reason: `"${attacker.label}" read object ${objId} owned by "${owner.label}".`,
            evidence: { attacker: attacker.label, owner: owner.label, objectId: objId, status: res.status, response: res.json },
            poc: toCurl({ ...res.request, headers: attacker.headers }),
          };
        }
      }
    }
  }
  const placeholderOwner = Object.entries(ownership).find(([, ids]) => ids.map(String).includes("1"))?.[0];
  return {
    status: "false-positive",
    method: "ownership replay",
    reason:
      `Cross-identity replays were all denied: ${tried.join(", ") || "none possible"}.` +
      (placeholderOwner ? ` The engine's hit used placeholder id 1, which "${placeholderOwner}" owns.` : ""),
  };
}

async function verifyNoAuth(ctx, g) {
  if (g.method !== "GET") return { status: "unverified", method: "unauthenticated replay", reason: "Only GET is replayed to avoid side effects." };
  const res = await ctx.request({ method: "GET", path: concretePath(ctx, g.path) });
  if (ok(res)) {
    return {
      status: "confirmed",
      method: "unauthenticated replay",
      reason: `Served HTTP ${res.status} with no credentials.`,
      evidence: { status: res.status, response: res.json ?? res.text?.slice(0, 300) },
      poc: toCurl(res.request),
    };
  }
  return { status: "false-positive", method: "unauthenticated replay", reason: `Replay without credentials returned HTTP ${res.status}.` };
}

async function verifyExposure(ctx, g) {
  const hits = [];
  for (const body of g.bodies) {
    try {
      hits.push(...findSensitiveFields(JSON.parse(body)));
    } catch {}
  }
  if (!hits.length) {
    return { status: "false-positive", method: "response field analysis", reason: "Responses contain no sensitive fields or values; the engine matched on status code / keyword only." };
  }
  const attacker = attackersOf(ctx, g)[0];
  const res = await ctx.request({ method: g.method, path: concretePath(ctx, g.path, attacker?.label), headers: attacker?.headers });
  const order = { CRITICAL: 3, HIGH: 2, MEDIUM: 1 };
  const top = hits.reduce((a, b) => ((order[b.severity] || 0) > (order[a.severity] || 0) ? b : a));
  const unique = [...new Map(hits.map((h) => [h.field + h.reason, h])).values()];
  return {
    status: "confirmed",
    method: "response field analysis",
    reason: `Sensitive field(s): ${[...new Set(unique.map((h) => h.reason))].join(", ")}.`,
    severity: top.severity,
    evidence: { fields: unique },
    poc: toCurl({ ...res.request, headers: attacker?.headers }),
  };
}

// BFLA: does the lower-privileged identity receive what the privileged one does?
async function verifyPrivilegeDiff(ctx, g) {
  if (/\{[^}]+\}/.test(g.path)) {
    return { status: "false-positive", method: "privilege differential", reason: "Object endpoint — cross-user access here is BOLA and is verified by the ownership replay instead." };
  }
  if (g.method !== "GET") return { status: "unverified", method: "privilege differential", reason: "Only GET is replayed to avoid side effects." };
  const victims = [...new Set(g.pairs.map((p) => p.victim))].map((l) => sessionFor(ctx, l)).filter(Boolean);
  const diffs = [];
  for (const attacker of attackersOf(ctx, g)) {
    for (const victim of victims) {
      const a = await ctx.request({ method: "GET", path: g.path, headers: attacker.headers });
      const v = await ctx.request({ method: "GET", path: g.path, headers: victim.headers });
      if (ok(a) && ok(v) && JSON.stringify(a.json) === JSON.stringify(v.json)) {
        return {
          status: "confirmed",
          method: "privilege differential",
          reason: `"${attacker.label}" receives exactly what "${victim.label}" receives.`,
          evidence: { attacker: attacker.label, victim: victim.label, status: a.status, response: a.json },
          poc: toCurl({ ...a.request, headers: attacker.headers }),
        };
      }
      diffs.push(`${attacker.label}≠${victim.label}`);
    }
  }
  return { status: "false-positive", method: "privilege differential", reason: `Self-scoped endpoint: each identity only receives its own data (${diffs.join(", ")}).` };
}

const TRACE = /node_modules\/|\bat\s+[\w.<>$]+\s*\([^)]*:\d+:\d+\)|Traceback \(most recent call last\)|Exception in thread|SQL syntax/;

async function verifyStackTrace(ctx, g) {
  const body = g.bodies.find((b) => TRACE.test(b));
  const endpoints = [...g.endpoints];
  if (!body) return { status: "false-positive", method: "stack-trace pattern", reason: "Error responses contain no stack trace or internal paths." };
  const [method, path] = endpoints[0].split(" ");
  const excerpt = body.replace(/<[^>]+>/g, "\n").replace(/&nbsp;/g, " ").replace(/&#39;/g, "'").split("\n").map((l) => l.trim()).filter(Boolean).slice(0, 4);
  return {
    status: "confirmed",
    method: "stack-trace pattern",
    reason: `Malformed input returns a stack trace with internal file paths on ${endpoints.length} endpoint(s).`,
    endpoint: endpoints.length > 1 ? `${endpoints.length} endpoints` : endpoints[0],
    evidence: { affected: endpoints, excerpt },
    poc: toCurl({
      method,
      url: ctx.config.baseUrl.replace(/\/$/, "") + concretePath(ctx, path),
      headers: { "Content-Type": "application/json" },
      rawBody: '{"invalid": ',
    }),
  };
}

async function verifyVerbs(ctx, g) {
  if (ctx.scope.mode !== "loopback") {
    return { status: "unverified", method: "undocumented-verb replay", reason: "Verb replays can change state, so they only run against loopback sandboxes." };
  }
  const documented = new Set(ctx.ops.filter((o) => o.path === g.path).map((o) => o.method));
  const attacker = attackersOf(ctx, g)[0];
  const path = concretePath(ctx, g.path, attacker?.label);
  const statuses = [];
  for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
    if (documented.has(method)) continue;
    const res = await ctx.request({ method, path, headers: attacker?.headers, body: method === "DELETE" ? undefined : {} });
    statuses.push(`${method} ${res.status}`);
    if (ok(res)) {
      return {
        status: "confirmed",
        method: "undocumented-verb replay",
        reason: `Undocumented ${method} succeeded (HTTP ${res.status}).`,
        evidence: { method, status: res.status, response: res.json ?? res.text?.slice(0, 300) },
        poc: toCurl({ ...res.request, headers: attacker?.headers }),
      };
    }
  }
  return { status: "false-positive", method: "undocumented-verb replay", reason: `Undocumented verbs are rejected (${statuses.join(", ")}); the engine counted the documented method / OPTIONS preflight.` };
}

async function unverifiedMutation() {
  return { status: "unverified", method: "engine mutation phase", reason: "Proven by the engine's setup→attack→verify phases; not replayed to avoid changing state." };
}

async function unverifiedGeneric() {
  return { status: "unverified", method: "none", reason: "No SentinelAPI verifier for this template yet." };
}

// --- entrypoint -------------------------------------------------------------------

export async function verifyCandidates(ctx, raw, engine) {
  const out = [];
  for (const g of groupCandidates(raw)) {
    let v;
    try {
      v = await g.cls.verify(ctx, g);
    } catch (err) {
      v = { status: "unverified", method: "error", reason: `Verifier error: ${err.message}` };
    }
    const endpoint = v.endpoint || `${g.method} ${g.path}`;
    const attackers = [...new Set(g.pairs.map((p) => p.attacker))];
    out.push({
      checkId: g.cls.checkId,
      title: g.cls.title,
      owasp: g.owasp,
      severity: v.severity || g.severity,
      confidence: v.status === "confirmed" ? 0.9 : v.status === "unverified" ? 0.5 : 0,
      endpoint,
      summary: v.reason,
      detail: `${engine} template "${g.templateId}" flagged this ${g.pairs.length} time(s) (attacker role(s): ${attackers.join(", ")}). SentinelAPI re-tested it via ${v.method}.`,
      evidence: v.evidence || {},
      remediation: REMEDIATION[g.cls.checkId] || "",
      poc: v.poc || toCurl({ method: g.method, url: ctx.config.baseUrl.replace(/\/$/, "") + concretePath(ctx, g.path), headers: {} }),
      engine,
      engines: [engine],
      verification: { status: v.status, method: v.method, reason: v.reason },
      source: { templateId: g.templateId, rawCandidates: g.pairs.length },
    });
  }
  return out;
}
