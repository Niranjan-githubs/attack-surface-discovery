// Phase 10: Predictive Directory Fuzzing.
// Reads Claude-written predictions from phase10_predictions.json (if present)
// AND a generic wordlist. Tests both against the live target.
//
// Node-based fuzzer with concurrency + jitter. Uses the 404 baseline from phase 3
// to filter out soft-404s.

const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const { loadConfig, readArtifact, writeArtifact, fetchWithTimeout, log, canonicalizePath, avoidReason } = require('./lib');

const GENERIC_WORDLIST = [
  'api', 'admin', 'login', 'logout', 'register', 'signup', 'signin', 'forgot-password', 'reset-password',
  'health', 'healthz', 'status', 'ping', 'metrics', 'info', 'version', 'robots.txt', 'sitemap.xml',
  'swagger', 'swagger.json', 'swagger-ui', 'swagger-ui.html', 'openapi.json', 'api-docs', 'docs',
  'graphql', 'graphiql', 'playground', 'altair',
  'users', 'user', 'profile', 'me', 'account', 'settings', 'preferences', 'dashboard',
  'products', 'items', 'catalog', 'inventory', 'orders', 'cart', 'checkout', 'payment',
  'upload', 'download', 'files', 'media', 'static', 'assets', 'public',
  'search', 'query', 'autocomplete', 'suggestions',
  'feedback', 'contact', 'support', 'help', 'about', 'terms', 'privacy',
  '.env', '.git/config', '.git/HEAD', '.DS_Store', 'config.json', 'package.json',
  'debug', 'dev', 'test', 'staging', 'internal', 'private',
  'v1', 'v2', 'v3', 'api/v1', 'api/v2', 'api/v3',
  'auth', 'auth/login', 'auth/logout', 'auth/refresh', 'auth/me', 'auth/register',
  'ws', 'websocket', 'socket.io',
  'rest', 'rpc', 'jsonrpc',
  'backup', 'backups', 'logs', 'log',
  'flag', 'flags', 'feature-flags',
  'admin/users', 'admin/dashboard', 'admin/settings', 'admin/logs',
  'report', 'reports', 'analytics', 'stats',
];

async function probe(target, url404Len, probePath, concurrency) {
  // Very small-batch fetch with jitter
  const full = new URL(probePath, target).toString();
  const jitter = 50 + Math.floor(Math.random() * 100);
  await new Promise(r => setTimeout(r, jitter));
  try {
    const res = await fetchWithTimeout(full, { method: 'GET', redirect: 'manual' }, 8000);
    const body = await res.text();
    // Heuristic: if matches baseline 404 length within 10%, treat as 404 regardless of code.
    const looksLike404 = url404Len && Math.abs(body.length - url404Len) / url404Len < 0.10;
    const status = res.status;
    return { path: probePath, status, length: body.length, looksLike404 };
  } catch (err) {
    return { path: probePath, status: 0, error: err.message };
  }
}

function parallelMap(items, fn, concurrency) {
  return new Promise((resolve, reject) => {
    const results = new Array(items.length);
    let idx = 0, running = 0, done = 0;
    const step = () => {
      while (running < concurrency && idx < items.length) {
        const i = idx++;
        running++;
        fn(items[i], i).then(r => {
          results[i] = r;
          running--; done++;
          if (done === items.length) resolve(results);
          else step();
        }, reject);
      }
    };
    if (items.length === 0) resolve([]);
    else step();
  });
}

(async () => {
  const cfg = loadConfig();
  const baseline = readArtifact('phase3_fingerprint.json');
  const crawl = readArtifact('phase7_crawl.json');
  const js = readArtifact('phase11_js.json');
  const predictionsArtifact = readArtifact('phase10_predictions.json');

  // Known paths — don't refuzz
  const known = new Set();
  for (const e of (crawl?.endpoints || [])) known.add(e.canonical);
  for (const e of (js?.endpoints || [])) known.add(canonicalizePath(e));

  // Build candidate list
  const predicted = (predictionsArtifact?.predictions || []).map(p => typeof p === 'string' ? p : p.path);
  const candidates = Array.from(new Set([...predicted, ...GENERIC_WORDLIST]))
    .map(p => p.startsWith('/') ? p : '/' + p)
    .filter(p => !known.has(canonicalizePath(p)))
    .filter(p => {
      const r = avoidReason(cfg, p);
      if (r) log(10, `skipping ${p}: ${r}`);
      return !r;
    });

  log(10, `${candidates.length} candidates to fuzz (predicted=${predicted.length}, generic=${GENERIC_WORDLIST.length})`);

  const baseline404Len = baseline?.patterns?.['404']?.typicalBodyLength || null;
  const concurrency = cfg.limits?.fuzzConcurrency || 4;

  const results = await parallelMap(candidates,
    (p) => probe(cfg.target, baseline404Len, p, concurrency),
    concurrency);

  const hits = results.filter(r => r.status && r.status < 400 && !r.looksLike404);
  const redirects = results.filter(r => r.status >= 300 && r.status < 400);
  const auth = results.filter(r => r.status === 401 || r.status === 403);

  writeArtifact('phase10_fuzz.json', {
    phase: 10,
    timestamp: new Date().toISOString(),
    candidatesTested: candidates.length,
    baselineBodyLength: baseline404Len,
    hits,
    redirects,
    authProtected: auth,
    newEndpoints: [...hits, ...auth].map(r => ({ canonical: canonicalizePath(r.path), status: r.status, discoveredBy: 'fuzzing' })),
  });
  log(10, `OK: ${hits.length} hits, ${redirects.length} redirects, ${auth.length} auth-gated`);
})();
