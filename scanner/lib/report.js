import { writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { rank, SEVERITY } from "./severity.js";

export function buildReport({ target, findings, filtered = [], engines = {}, checksRun, startedAt }) {
  const ranked = rank(findings);
  const counts = {};
  for (const key of Object.keys(SEVERITY)) counts[key] = 0;
  for (const f of ranked) counts[f.severity] = (counts[f.severity] || 0) + 1;

  return {
    tool: "SentinelAPI",
    version: "0.2.0",
    target,
    startedAt,
    finishedAt: new Date().toISOString(),
    checksRun,
    engines,
    summary: {
      total: ranked.length,
      counts,
      highestSeverity: ranked[0]?.severity || "NONE",
      corroborated: ranked.filter((f) => f.engines?.length > 1).length,
      filtered: filtered.length,
    },
    findings: ranked,
    // Engine candidates SentinelAPI disproved or merged, kept for transparency.
    filtered,
  };
}

export async function writeReport(report, jsonPath) {
  await mkdir(dirname(jsonPath), { recursive: true });
  await writeFile(jsonPath, JSON.stringify(report, null, 2), "utf8");
}
