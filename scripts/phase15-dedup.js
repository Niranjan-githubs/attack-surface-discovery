// Phase 15: Endpoint Deduplication & Merge. The master inventory.

const { readArtifact, writeArtifact, log, canonicalizePath } = require('./lib');

(async () => {
  const sources = {
    crawl: readArtifact('phase7_crawl.json'),
    classify: readArtifact('phase8_classify.json'),
    historical: readArtifact('phase9_historical.json'),
    fuzz: readArtifact('phase10_fuzz.json'),
    js: readArtifact('phase11_js.json'),
    apidocs: readArtifact('phase12_apidocs.json'),
    traffic: readArtifact('phase13_traffic.json'),
  };

  const merged = new Map(); // canonical -> { canonical, methods:Set, sources:Set, role_access, statuses:Set }

  function add(canonical, method, source, extra = {}) {
    if (!canonical) return;
    if (!merged.has(canonical)) {
      merged.set(canonical, {
        canonical,
        methods: new Set(),
        sources: new Set(),
        statuses: new Set(),
        roleAccess: {},
      });
    }
    const entry = merged.get(canonical);
    if (method) entry.methods.add(method);
    entry.sources.add(source);
    if (extra.status) entry.statuses.add(extra.status);
    if (extra.role && extra.status) {
      entry.roleAccess[extra.role] = extra.status;
    }
  }

  for (const e of (sources.crawl?.endpoints || [])) {
    for (const m of (e.methods || ['GET'])) add(e.canonical, m, 'active-crawl', { role: e.role });
  }
  for (const r of (sources.traffic?.requests || [])) {
    add(r.path, r.method, 'traffic', { status: r.status, role: r.role });
  }
  for (const e of (sources.fuzz?.newEndpoints || [])) {
    add(e.canonical, 'GET', 'fuzzing', { status: e.status });
  }
  for (const e of (sources.js?.endpoints || [])) {
    add(canonicalizePath(e), 'GET', 'js-analysis');
  }
  for (const e of (sources.apidocs?.endpoints || [])) {
    add(e.canonical, e.method, e.discoveredBy || 'api-spec');
  }
  for (const h of (sources.historical?.stillLive || [])) {
    add(canonicalizePath(h.path), 'GET', 'wayback', { status: h.status });
  }

  // Apply classify matrix for role access
  if (sources.classify?.matrix) {
    for (const [canonical, perRole] of Object.entries(sources.classify.matrix)) {
      if (!merged.has(canonical)) add(canonical, 'GET', 'classify-probe');
      const entry = merged.get(canonical);
      for (const [role, info] of Object.entries(perRole)) {
        entry.roleAccess[role] = info.status;
      }
    }
  }

  const endpoints = Array.from(merged.values()).map(e => ({
    canonical: e.canonical,
    methods: Array.from(e.methods).sort(),
    sources: Array.from(e.sources).sort(),
    statuses: Array.from(e.statuses).sort(),
    roleAccess: e.roleAccess,
    confidence: e.sources.size >= 2 ? 'high' : 'medium',
  })).sort((a, b) => a.canonical.localeCompare(b.canonical));

  writeArtifact('phase15_endpoints.json', {
    phase: 15,
    timestamp: new Date().toISOString(),
    totalEndpoints: endpoints.length,
    bySource: Object.fromEntries(
      Array.from(new Set(endpoints.flatMap(e => e.sources))).map(s => [s, endpoints.filter(e => e.sources.includes(s)).length])
    ),
    endpoints,
  });
  log(15, `OK: ${endpoints.length} unique endpoints from ${endpoints.flatMap(e => e.sources).filter((v,i,a)=>a.indexOf(v)===i).length} sources`);
})();
