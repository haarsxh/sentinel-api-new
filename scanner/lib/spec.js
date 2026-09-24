// Minimal OpenAPI (3.x / Swagger 2.0) reader — just what the checks need.

import { readFile } from "node:fs/promises";

export async function loadSpec(specPath) {
  const raw = await readFile(specPath, "utf8");
  const spec = JSON.parse(raw);
  return spec;
}

// Flatten paths into a list of operations we can iterate over.
export function operations(spec) {
  const out = [];
  const paths = spec.paths || {};
  for (const [path, methods] of Object.entries(paths)) {
    for (const [method, op] of Object.entries(methods)) {
      if (!["get", "post", "put", "patch", "delete"].includes(method)) continue;
      out.push({
        path,
        method: method.toUpperCase(),
        summary: op.summary || "",
        parameters: op.parameters || [],
        security: op.security ?? spec.security ?? [],
        raw: op,
      });
    }
  }
  return out;
}

// Path params that look like object identifiers (candidates for BOLA testing).
export function objectIdParams(op) {
  return (op.parameters || []).filter((p) => p.in === "path");
}

export function isSecured(op) {
  return Array.isArray(op.security) && op.security.length > 0;
}
