import { writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { rank, SEVERITY } from "./severity.js";

export function buildReport({ target, findings, checksRun, startedAt }) {
  const ranked = rank(findings);
  const counts = {};
  for (const key of Object.keys(SEVERITY)) counts[key] = 0;
  for (const f of ranked) counts[f.severity] = (counts[f.severity] || 0) + 1;

  return {
    tool: "SentinelAPI",
    version: "0.1.0",
    target,
    startedAt,
    finishedAt: new Date().toISOString(),
    checksRun,
    summary: {
      total: ranked.length,
      counts,
      highestSeverity: ranked[0]?.severity || "NONE",
    },
    findings: ranked,
  };
}

export async function writeReport(report, jsonPath) {
  await mkdir(dirname(jsonPath), { recursive: true });
  await writeFile(jsonPath, JSON.stringify(report, null, 2), "utf8");
}
