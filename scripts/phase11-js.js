// Phase 11: JavaScript Static Analysis — endpoints + secrets from JS bundles.

const { URL } = require('url');
const {
  loadConfig, readArtifact, writeArtifact, fetchWithTimeout, log,
  canonicalizePath, isSameOrigin,
} = require('./lib');

// Endpoint patterns — match /something/... or /api/... in string literals
const ENDPOINT_RE = /['"`](\/(?:api\/)?[a-zA-Z0-9_\-\/]{2,}[a-zA-Z0-9_\-])['"`]/g;
const ROUTE_RE = /(?:fetch|axios(?:\.(?:get|post|put|patch|delete))?|\.url\s*=|path\s*:)\s*\(?\s*['"`]([^'"`\s]+)['"`]/g;

// Secret regex patterns — conservative to reduce false positives
const SECRET_PATTERNS = [
  { name: 'AWS Access Key', re: /\bAKIA[0-9A-Z]{16}\b/g, severity: 'critical' },
  { name: 'AWS Secret', re: /\b[A-Za-z0-9/+=]{40}\b(?=.*aws|aws.*)/gi, severity: 'high' },
  { name: 'Google API Key', re: /\bAIza[0-9A-Za-z_\-]{35}\b/g, severity: 'high' },
  { name: 'Stripe Secret', re: /\bsk_live_[0-9a-zA-Z]{24,}\b/g, severity: 'critical' },
  { name: 'Stripe Publishable', re: /\bpk_live_[0-9a-zA-Z]{24,}\b/g, severity: 'low' },
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, severity: 'medium' },
  { name: 'GitHub Token', re: /\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/g, severity: 'critical' },
  { name: 'Slack Token', re: /\bxox[abp]-[A-Za-z0-9\-]{10,}\b/g, severity: 'high' },
  { name: 'Private Key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, severity: 'critical' },
];

function extractEndpoints(source) {
  const found = new Set();
  let m;
  ENDPOINT_RE.lastIndex = 0;
  while ((m = ENDPOINT_RE.exec(source)) !== null) {
    found.add(m[1]);
  }
  ROUTE_RE.lastIndex = 0;
  while ((m = ROUTE_RE.exec(source)) !== null) {
    if (m[1].startsWith('/')) found.add(m[1]);
  }
  return Array.from(found);
}

function extractSecrets(source, fileUrl) {
  const hits = [];
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    let m;
    while ((m = p.re.exec(source)) !== null) {
      hits.push({
        type: p.name,
        severity: p.severity,
        snippet: m[0].slice(0, 20) + '...',
        sourceFile: fileUrl,
      });
    }
  }
  return hits;
}

(async () => {
  const cfg = loadConfig();
  const meta = readArtifact('phase2_metadata.json');
  const crawl = readArtifact('phase7_crawl.json');

  // Collect JS URLs from phase 2 + traffic artifact
  const jsUrls = new Set();
  for (const src of (meta?.scripts || [])) {
    try {
      const abs = new URL(src, cfg.target).toString();
      if (isSameOrigin(cfg.target, abs)) jsUrls.add(abs);
    } catch {}
  }
  const traffic = readArtifact('phase13_traffic.json');
  for (const r of (traffic?.requests || [])) {
    if (r.resourceType === 'script' && isSameOrigin(cfg.target, r.url)) jsUrls.add(r.url);
  }
  log(11, `analyzing ${jsUrls.size} JS files`);

  const endpoints = new Set();
  const secrets = [];
  const analyzed = [];

  for (const url of jsUrls) {
    try {
      const res = await fetchWithTimeout(url, {}, 20000);
      if (!res.ok) { analyzed.push({ url, status: res.status, skipped: true }); continue; }
      const source = await res.text();
      const eps = extractEndpoints(source);
      for (const e of eps) endpoints.add(e);
      const ss = extractSecrets(source, url);
      secrets.push(...ss);
      analyzed.push({ url, status: res.status, size: source.length, endpointsFound: eps.length, secretsFound: ss.length });
    } catch (err) {
      analyzed.push({ url, error: err.message });
    }
  }

  // Derive API base paths: prefixes shared by 2+ extracted endpoints (and ≥1 segment deep).
  const endpointList = Array.from(endpoints).sort();
  const prefixCount = new Map();
  for (const ep of endpointList) {
    const parts = ep.split('/').filter(Boolean);
    for (let depth = 1; depth <= Math.min(3, parts.length - 1); depth++) {
      const prefix = '/' + parts.slice(0, depth).join('/');
      prefixCount.set(prefix, (prefixCount.get(prefix) || 0) + 1);
    }
  }
  const apiBasePaths = Array.from(prefixCount.entries())
    .filter(([prefix, count]) => count >= 2 && /^\/(api|v\d|graphql|rest|rpc)/i.test(prefix))
    .sort((a, b) => b[1] - a[1])
    .map(([prefix, count]) => ({ prefix, endpointsSharing: count }));

  // Client-side route definitions: look for SPA route-config patterns in JS.
  // Patterns: {path: '/foo'}, route('/foo'), when('/foo'), redirectTo: '/foo', {href: '/foo'} in JSX/template
  const clientRoutes = new Set();
  const ROUTE_CONFIG_RE = /(?:path|route|when|redirectTo)\s*:\s*['"`](\/[^'"`\s?#]{1,80})['"`]/g;
  const ROUTE_FN_RE = /\.(?:route|when|navigate|push|replace)\(\s*['"`](\/[^'"`\s?#]{1,80})['"`]/g;
  const HASH_ROUTE_RE = /['"`](\/#\/[^'"`\s?#]{1,80})['"`]/g;
  for (const entry of analyzed) {
    if (!entry.url || entry.skipped || entry.error) continue;
    try {
      // re-read via the already-downloaded source (we don't cache; skip if too large)
      // We can extract from endpoints[] that start with / but aren't /api — those are likely SPA routes
    } catch {}
  }
  // Heuristic from already-extracted endpoints: anything /foo that isn't /api/* or /v\d/* or /resources/*
  for (const ep of endpointList) {
    if (/^\/(api|v\d|graphql|rest|rpc|resources|static|assets|public|image|images|js|css|fonts?)\b/i.test(ep)) continue;
    if (ep.startsWith('/#/') || (!ep.includes('.') && ep.split('/').length <= 4)) clientRoutes.add(ep);
  }

  writeArtifact('phase11_js.json', {
    phase: 11,
    timestamp: new Date().toISOString(),
    filesAnalyzed: analyzed.length,
    files: analyzed,
    endpoints: endpointList,
    apiBasePaths,
    clientRoutes: Array.from(clientRoutes).sort(),
    secrets,
  });
  log(11, `OK: ${endpoints.size} endpoint candidates, ${apiBasePaths.length} API base paths, ${clientRoutes.size} client routes, ${secrets.length} secret hits`);
})();
