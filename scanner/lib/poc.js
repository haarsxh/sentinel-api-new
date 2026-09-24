// Build a copy-pasteable curl command from a recorded request, so every finding
// ships with reproduction steps rather than just "vulnerability detected".

export function toCurl(req, { redact = true } = {}) {
  if (!req) return "";
  const parts = [`curl -i -X ${req.method}`];
  for (const [k, v] of Object.entries(req.headers || {})) {
    let value = v;
    if (redact && /authorization/i.test(k)) {
      // Keep the scheme, mask the token so PoCs are safe to paste into reports.
      value = String(v).replace(/(\S+\s+).*/, "$1<REDACTED_TOKEN>");
    }
    parts.push(`-H '${k}: ${value}'`);
  }
  if (req.body) parts.push(`-d '${JSON.stringify(req.body)}'`);
  parts.push(`'${req.url}'`);
  return parts.join(" ");
}
