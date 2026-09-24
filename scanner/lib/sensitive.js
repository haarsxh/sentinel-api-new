// Heuristics for spotting sensitive fields in API responses (excessive data exposure).
// Kept conservative to limit false positives — a scanner that cries wolf gets ignored.

const SENSITIVE_KEYS = [
  { key: /^password$|passwd|pwd/i, label: "password", severity: "CRITICAL" },
  { key: /ssn|social.?security/i, label: "government id / SSN", severity: "CRITICAL" },
  { key: /(^|_)secret|api.?token|apitoken|access.?token|refresh.?token|private.?key/i, label: "credential / token", severity: "HIGH" },
  { key: /card|ccnum|creditcard|pan\b/i, label: "payment card", severity: "HIGH" },
  { key: /^cvv$|cvc/i, label: "card verification value", severity: "CRITICAL" },
];

// Value-shape signals (catches leaks where the key name is innocuous).
const SENSITIVE_VALUES = [
  { re: /\b\d{3}-\d{2}-\d{4}\b/, label: "SSN-shaped value", severity: "CRITICAL" },
  { re: /\b(?:\d[ -]?){13,16}\b/, label: "card-number-shaped value", severity: "HIGH" },
];

export function findSensitiveFields(obj, path = "") {
  const hits = [];
  if (obj == null) return hits;

  if (Array.isArray(obj)) {
    obj.forEach((v, i) => hits.push(...findSensitiveFields(v, `${path}[${i}]`)));
    return hits;
  }
  if (typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      const here = path ? `${path}.${k}` : k;
      for (const rule of SENSITIVE_KEYS) {
        if (rule.key.test(k)) hits.push({ field: here, reason: rule.label, severity: rule.severity });
      }
      hits.push(...findSensitiveFields(v, here));
    }
    return hits;
  }
  if (typeof obj === "string") {
    for (const rule of SENSITIVE_VALUES) {
      if (rule.re.test(obj)) hits.push({ field: path, reason: rule.label, severity: rule.severity });
    }
  }
  return hits;
}
