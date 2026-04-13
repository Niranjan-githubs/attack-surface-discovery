// Phase 14: Parameter Mutation Analysis.
// Classify parameters as static/dynamic/unknown by observing across requests.

const { URL } = require('url');
const { readArtifact, writeArtifact, log } = require('./lib');

const DYNAMIC_NAME_RE = /^(id|_id|uuid|token|csrf|_csrf|xsrf|nonce|timestamp|ts|time|hash|sig|signature|rnd|random|state|session|sid|sessid)$/i;
const STATIC_NAME_RE = /^(lang|locale|version|v|format|type|category|page|limit|offset|sort|order|q|query)$/i;

function classifyParam(name, values) {
  const unique = new Set(values.filter(v => v != null && v !== ''));
  if (DYNAMIC_NAME_RE.test(name)) return 'dynamic';
  if (STATIC_NAME_RE.test(name)) return 'static';
  if (unique.size <= 1) return 'static';
  if (unique.size >= Math.max(3, values.length * 0.6)) return 'dynamic';
  return 'unknown';
}

function detectType(name, values) {
  if (DYNAMIC_NAME_RE.test(name)) {
    if (/csrf|xsrf/i.test(name)) return 'csrf-token';
    if (/^id$|_id$/i.test(name)) return 'identifier';
    if (/token/i.test(name)) return 'token';
    if (/timestamp|ts|time/i.test(name)) return 'timestamp';
  }
  // JWT shape
  if (values.some(v => typeof v === 'string' && /^eyJ[A-Za-z0-9_-]+\./.test(v))) return 'jwt';
  return null;
}

(async () => {
  const traffic = readArtifact('phase13_traffic.json');
  if (!traffic) throw new Error('phase13 artifact missing (traffic capture failed in phase 7)');

  // Collect query params and form/body params per (canonical path, param name)
  const params = new Map(); // key = "canon|name" -> { name, path, values:[], inBody:bool }

  for (const req of traffic.requests) {
    try {
      const u = new URL(req.url);
      for (const [k, v] of u.searchParams.entries()) {
        const key = `${req.path}|${k}`;
        if (!params.has(key)) params.set(key, { name: k, path: req.path, values: [], where: 'query' });
        params.get(key).values.push(v);
      }
    } catch {}
    if (req.postData) {
      // Try JSON, then form-encoded
      try {
        const parsed = JSON.parse(req.postData);
        if (typeof parsed === 'object' && parsed !== null) {
          for (const [k, v] of Object.entries(parsed)) {
            const key = `${req.path}|${k}`;
            if (!params.has(key)) params.set(key, { name: k, path: req.path, values: [], where: 'body-json' });
            params.get(key).values.push(v);
          }
        }
      } catch {
        try {
          const usp = new URLSearchParams(req.postData);
          for (const [k, v] of usp.entries()) {
            const key = `${req.path}|${k}`;
            if (!params.has(key)) params.set(key, { name: k, path: req.path, values: [], where: 'body-form' });
            params.get(key).values.push(v);
          }
        } catch {}
      }
    }
  }

  const classified = Array.from(params.values()).map(p => ({
    path: p.path,
    name: p.name,
    where: p.where,
    occurrences: p.values.length,
    classification: classifyParam(p.name, p.values),
    semanticType: detectType(p.name, p.values),
    sampleValues: Array.from(new Set(p.values.slice(0, 5).map(v => String(v).slice(0, 40)))),
  }));

  const counts = classified.reduce((acc, p) => {
    acc[p.classification] = (acc[p.classification] || 0) + 1;
    return acc;
  }, {});

  writeArtifact('phase14_params.json', {
    phase: 14,
    timestamp: new Date().toISOString(),
    totalParams: classified.length,
    counts,
    params: classified,
    coverage: classified.length ? (1 - (counts.unknown || 0) / classified.length) : 0,
  });
  log(14, `OK: ${classified.length} parameters classified (${JSON.stringify(counts)})`);
})();
