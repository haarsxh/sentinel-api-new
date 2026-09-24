// Appends the latest scan summary to the published findings history.
//
// Usage: node scripts/append-history.mjs <previous-history-url> <latest.json> <out.json>
// The previous history is fetched from the live site; a missing or unreadable one
// simply starts a new history.

import { readFile, writeFile } from "node:fs/promises";

const [prevUrl, latestPath, outPath] = process.argv.slice(2);
const KEEP = 90;

let history = [];
try {
  const res = await fetch(prevUrl, { cache: "no-store" });
  if (res.ok) history = await res.json();
  if (!Array.isArray(history)) history = [];
} catch {}

const report = JSON.parse(await readFile(latestPath, "utf8"));
history.push({
  finishedAt: report.finishedAt,
  total: report.summary.total,
  counts: report.summary.counts,
  filtered: report.summary.filtered,
  commit: process.env.GITHUB_SHA?.slice(0, 7),
});

await writeFile(outPath, JSON.stringify(history.slice(-KEEP)));
console.log(`[history] ${history.length} run(s) recorded`);
