// Hadrian engine adapter.
//
// Hadrian (https://github.com/praetorian-inc/hadrian, Apache-2.0) is an external,
// template-driven API authorization tester. SentinelAPI does not bundle it: it runs
// the installed `hadrian` binary as a subprocess, feeds it configuration generated
// from our own target file, and hands its raw findings to the verifier.
//
// Credentials handed to Hadrian are written to a private (0700) temp directory with
// 0600 files and removed as soon as the run finishes, so the scanner never leaves
// tokens on disk.

import { spawn } from "node:child_process";
import { mkdtemp, writeFile, readFile, readdir, rm, access, chmod } from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join, resolve, delimiter } from "node:path";

export const id = "hadrian";

// Templates that mutate or delete state. Only run against loopback sandboxes
// unless the target config explicitly opts in.
const DESTRUCTIVE = /delete|write|verb-tampering|method-override/i;

async function exists(p) {
  try {
    await access(p, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export async function locateBinary(config = {}) {
  const candidates = [
    config.hadrian?.bin,
    process.env.HADRIAN_BIN,
    ...(process.env.PATH || "").split(delimiter).map((d) => join(d, "hadrian")),
    join(process.env.GOPATH || join(homedir(), "go"), "bin", "hadrian"),
  ].filter(Boolean);
  for (const c of candidates) if (await exists(c)) return c;
  return null;
}

export async function locateTemplates(root, config = {}) {
  const candidates = [
    config.hadrian?.templateDir && resolve(root, config.hadrian.templateDir),
    process.env.HADRIAN_TEMPLATES,
    resolve(root, ".hadrian/src/templates/rest"),
  ].filter(Boolean);
  for (const c of candidates) {
    try {
      const files = await readdir(c);
      if (files.some((f) => f.endsWith(".yaml"))) return c;
    } catch {}
  }
  return null;
}

// Minimal YAML emitter for the flat structures Hadrian's config needs.
// Values are always JSON-quoted, which is valid YAML and immune to injection.
const q = (v) => JSON.stringify(String(v));

// roles.yaml: one Hadrian role per SentinelAPI identity. `level` orders privilege;
// Hadrian pairs lower-level attackers against higher-level victims.
export function buildRolesYaml(config) {
  const objects = [
    ...new Set(Object.keys(config.seededObjectIds || {}).map((p) => p.split("/").filter(Boolean)[0])),
  ];
  const lines = [`objects: [${objects.map(q).join(", ")}]`, "roles:"];
  for (const ident of config.identities || []) {
    const level = ident.level ?? 10;
    const scope = level >= 100 ? "all" : "own";
    const perms = objects.map((o) => q(`read:${o}:${scope}`));
    lines.push(`  - name: ${q(ident.label)}`, `    level: ${level}`, `    permissions: [${perms.join(", ")}]`);
  }
  return lines.join("\n") + "\n";
}

// auth.yaml: reuse the sessions SentinelAPI already established (login or token).
export function buildAuthYaml(config, sessions) {
  const auth = config.auth || {};
  const scheme = auth.scheme ?? "Bearer";
  const header = auth.header || "Authorization";
  const bearer = /^bearer$/i.test(scheme) && /^authorization$/i.test(header);

  const lines = bearer
    ? ["method: bearer"]
    : ["method: api_key", "location: header", `key_name: ${q(header)}`];
  lines.push("roles:");
  for (const s of sessions) {
    const raw = s.authHeader || "";
    const value = bearer ? raw.replace(/^Bearer\s+/i, "") : raw;
    lines.push(`  ${q(s.label)}:`, bearer ? `    token: ${q(value)}` : `    api_key: ${q(value)}`);
  }
  return lines.join("\n") + "\n";
}

function runProcess(cmd, args, { timeoutMs }) {
  return new Promise((res) => {
    const p = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (out += d));
    const timer = setTimeout(() => p.kill("SIGKILL"), timeoutMs);
    p.on("close", (code) => {
      clearTimeout(timer);
      res({ code, out });
    });
  });
}

// Runs Hadrian and returns its raw, unverified findings (is_vulnerability only).
export async function run({ root, config, spec, sessions, scope }) {
  const bin = await locateBinary(config);
  if (!bin) throw new Error("hadrian binary not found (run: npm run setup:hadrian)");
  const templateDir = await locateTemplates(root, config);
  if (!templateDir) throw new Error("hadrian templates not found (run: npm run setup:hadrian)");

  const allowDestructive = scope.mode === "loopback" || config.hadrian?.allowDestructive === true;
  const templateIds = (await readdir(templateDir))
    .filter((f) => f.endsWith(".yaml"))
    .map((f) => f.replace(/\.yaml$/, ""))
    .filter((t) => allowDestructive || !DESTRUCTIVE.test(t))
    .filter((t) => !config.hadrian?.templates || config.hadrian.templates.includes(t));

  const work = await mkdtemp(join(tmpdir(), "sentinel-hadrian-"));
  await chmod(work, 0o700);
  try {
    // Pin Hadrian to the configured baseUrl regardless of the spec's `servers`.
    const specPath = join(work, "openapi.json");
    await writeFile(specPath, JSON.stringify({ ...spec, servers: [{ url: config.baseUrl }] }));
    const rolesPath = join(work, "roles.yaml");
    await writeFile(rolesPath, buildRolesYaml(config));
    const authPath = join(work, "auth.yaml");
    await writeFile(authPath, buildAuthYaml(config, sessions), { mode: 0o600 });
    const outPath = join(work, "findings.json");

    const args = [
      "--no-banner", "test", "rest",
      "--api", specPath,
      "--roles", rolesPath,
      "--auth", authPath,
      "--template-dir", templateDir,
      "--template", templateIds.join(","),
      "--rate-limit", String(config.hadrian?.rateLimit ?? 10),
      "--timeout", String(config.hadrian?.timeoutSec ?? 10),
      "--audit-log", join(work, "audit.log"),
      "--output", "json",
      "--output-file", outPath,
    ];
    const { code, out } = await runProcess(bin, args, { timeoutMs: (config.hadrian?.maxRuntimeSec ?? 300) * 1000 });

    let raw;
    try {
      raw = JSON.parse(await readFile(outPath, "utf8"));
    } catch {
      throw new Error(`hadrian produced no report (exit ${code}): ${out.trim().split("\n").slice(-3).join(" | ")}`);
    }
    return {
      templates: templateIds,
      stats: raw.stats || {},
      findings: (raw.findings || []).filter((f) => f.is_vulnerability),
    };
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
