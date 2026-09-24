// Self-test: proves the scanner detects each seeded vulnerability class in the
// bundled demo target, and does NOT flag the secure control endpoints.
// Used by CI. Exits 0 on success, 1 on any assertion failure.

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function run(cmd, args, opts = {}) {
  return new Promise((res) => {
    const p = spawn(cmd, args, { cwd: ROOT, ...opts });
    let out = "";
    p.stdout?.on("data", (d) => (out += d));
    p.stderr?.on("data", (d) => (out += d));
    p.on("close", (code) => res({ code, out }));
  });
}

async function waitForHealth(url, tries = 30) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url);
      if (r.ok) return true;
    } catch {}
    await sleep(200);
  }
  return false;
}

let failures = 0;
function assert(cond, msg) {
  if (cond) console.log(`  ✓ ${msg}`);
  else { console.error(`  ✗ ${msg}`); failures++; }
}

async function main() {
  console.log("[selftest] starting demo target …");
  const demo = spawn("node", ["demo-api/server.js"], { cwd: ROOT, stdio: "ignore" });

  try {
    const up = await waitForHealth("http://127.0.0.1:4000/health");
    if (!up) throw new Error("demo target did not become healthy");

    console.log("[selftest] running scan …");
    const scan = await run("node", ["scanner/cli.js", "--config", "scanner/targets/demo.json"]);
    // Exit code 2 is expected here: the demo is intentionally vulnerable.
    assert(scan.code === 2, "scanner exits non-zero (2) when findings meet the gate");

    const report = JSON.parse(await readFile(resolve(ROOT, "report/data/latest.json"), "utf8"));
    const byCheck = new Set(report.findings.map((f) => f.checkId));

    console.log("[selftest] asserting each vulnerability class is detected …");
    assert(byCheck.has("bola"), "detects broken object-level authorization (IDOR)");
    assert(byCheck.has("data-exposure"), "detects excessive data exposure");
    assert(byCheck.has("missing-auth"), "detects missing authentication enforcement");
    assert(byCheck.has("rate-limit"), "detects missing rate limiting");

    console.log("[selftest] asserting no false positives on secure controls …");
    const endpoints = report.findings.map((f) => f.endpoint);
    assert(!endpoints.some((e) => e.includes("/my/orders")), "does NOT flag secure /my/orders");
    assert(!endpoints.some((e) => e.includes("/profile")), "does NOT flag secure /profile");

    assert(report.summary.highestSeverity === "CRITICAL", "reports CRITICAL as highest severity");
  } catch (err) {
    console.error(`[selftest] error: ${err.message}`);
    failures++;
  } finally {
    demo.kill();
  }

  console.log(failures === 0 ? "\n[selftest] PASS" : `\n[selftest] FAIL (${failures})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
