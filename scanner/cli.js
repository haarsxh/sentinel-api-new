#!/usr/bin/env node
// SentinelAPI scanner entrypoint.
//
// Usage:
//   node scanner/cli.js --config scanner/targets/demo.json [--out report/data/latest.json] [--fail-on high]
//
// Exit code is non-zero when findings at/above --fail-on are present, so it can gate CI.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { assertAuthorized } from "./lib/safety.js";
import { loadSpec, operations } from "./lib/spec.js";
import { establishSessions } from "./lib/auth.js";
import { request as httpRequest } from "./lib/http.js";
import { buildReport, writeReport } from "./lib/report.js";
import { SEVERITY } from "./lib/severity.js";

import * as bola from "./checks/bola.js";
import * as dataExposure from "./checks/dataExposure.js";
import * as missingAuth from "./checks/missingAuth.js";
import * as rateLimit from "./checks/rateLimit.js";

const CHECKS = [bola, dataExposure, missingAuth, rateLimit];
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) args[argv[i].slice(2)] = argv[i + 1]?.startsWith("--") || argv[i + 1] === undefined ? true : argv[++i];
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const configPath = args.config || "scanner/targets/demo.json";
  const outPath = args.out || "report/data/latest.json";
  const failOn = String(args["fail-on"] || "high").toUpperCase();

  const config = JSON.parse(await readFile(resolve(ROOT, configPath), "utf8"));

  // --- safety gate: refuse unauthorized targets --------------------------------
  const scope = assertAuthorized(config);
  console.log(`[sentinel] target ${config.baseUrl} (${scope.mode})`);

  const startedAt = new Date().toISOString();
  const spec = await loadSpec(resolve(ROOT, config.specPath));
  const ops = operations(spec);
  console.log(`[sentinel] loaded ${ops.length} operations from spec`);

  const sessions = await establishSessions(config);
  console.log(`[sentinel] established ${sessions.length} authenticated session(s): ${sessions.map((s) => s.label).join(", ")}`);

  const request = (opts) => httpRequest(config.baseUrl, opts);
  const ctx = { config, spec, ops, sessions, request };

  const findings = [];
  const checksRun = [];
  for (const check of CHECKS) {
    process.stdout.write(`[sentinel] running check "${check.id}" ... `);
    try {
      const results = await check.run(ctx);
      findings.push(...results);
      checksRun.push(check.id);
      console.log(`${results.length} finding(s)`);
    } catch (err) {
      console.log(`error: ${err.message}`);
    }
  }

  const report = buildReport({
    target: { baseUrl: config.baseUrl, name: config.name || "target" },
    findings,
    checksRun,
    startedAt,
  });

  await writeReport(report, resolve(ROOT, outPath));

  // --- console summary ---------------------------------------------------------
  console.log("\n=== SentinelAPI summary ===");
  console.log(`Target: ${config.baseUrl}`);
  console.log(`Findings: ${report.summary.total} (highest: ${report.summary.highestSeverity})`);
  for (const [sev, n] of Object.entries(report.summary.counts)) {
    if (n > 0) console.log(`  ${SEVERITY[sev].label}: ${n}`);
  }
  console.log(`Report written to ${outPath}`);

  // --- CI gate -----------------------------------------------------------------
  const threshold = SEVERITY[failOn]?.score ?? SEVERITY.HIGH.score;
  const gating = findings.filter((f) => (SEVERITY[f.severity]?.score || 0) >= threshold);
  if (gating.length > 0) {
    console.error(`\n[sentinel] ${gating.length} finding(s) at or above ${failOn} — failing.`);
    process.exit(2);
  }
}

main().catch((err) => {
  console.error(`[sentinel] fatal: ${err.message}`);
  process.exit(1);
});
