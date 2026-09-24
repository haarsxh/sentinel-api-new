// Severity model. Each check assigns a base severity; we keep a numeric score
// so findings sort deterministically and the dashboard can rank them.

export const SEVERITY = {
  CRITICAL: { label: "Critical", score: 9 },
  HIGH: { label: "High", score: 7 },
  MEDIUM: { label: "Medium", score: 5 },
  LOW: { label: "Low", score: 3 },
  INFO: { label: "Info", score: 1 },
};

export function rank(findings) {
  return [...findings].sort((a, b) => {
    const s = (SEVERITY[b.severity]?.score || 0) - (SEVERITY[a.severity]?.score || 0);
    if (s !== 0) return s;
    return (b.confidence || 0) - (a.confidence || 0);
  });
}
