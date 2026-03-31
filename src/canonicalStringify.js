/**
 * Deterministic JSON for RSA signing (sorted keys, no whitespace drift).
 */
export function canonicalStringify(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalStringify(v)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  const parts = keys.map((k) => `${JSON.stringify(k)}:${canonicalStringify(value[k])}`);
  return `{${parts.join(',')}}`;
}
