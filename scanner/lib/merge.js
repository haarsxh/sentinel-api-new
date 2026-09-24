// Cross-engine merge.
//
// When an external engine's verified finding matches a native finding (same class,
// same endpoint), keep the native one — it already carries ownership-aware evidence —
// and record that a second, independent engine corroborated it.

const key = (f) => `${f.checkId}|${f.endpoint}`;

export function mergeEngines(native, external) {
  const byKey = new Map(native.map((f) => [key(f), f]));
  const kept = [...native];
  const filtered = [];

  for (const f of external) {
    if (f.verification.status === "false-positive") {
      filtered.push(f);
      continue;
    }
    const twin = byKey.get(key(f));
    if (twin) {
      if (!twin.engines.includes(f.engine)) twin.engines.push(f.engine);
      twin.confidence = Math.min(0.99, (twin.confidence || 0) + 0.04);
      twin.verification.corroboratedBy = [...(twin.verification.corroboratedBy || []), f.engine];
      filtered.push({ ...f, verification: { ...f.verification, status: "duplicate", reason: `Same issue already confirmed by the native engine (${twin.checkId} on ${twin.endpoint}).` } });
      continue;
    }
    kept.push(f);
  }
  return { findings: kept, filtered };
}
