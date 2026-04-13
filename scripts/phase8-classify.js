// Phase 8: Response Classification — probe every endpoint per role + unauthenticated.
// Parallel (configurable concurrency) with progress logging every 10 endpoints.

const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');
const {
  loadConfig, readArtifact, writeArtifact, log, AUTH_DIR,
} = require('./lib');

function parallelMap(items, concurrency, fn) {
  return new Promise((resolve, reject) => {
    const results = new Array(items.length);
    let idx = 0, running = 0, done = 0;
    const step = () => {
      while (running < concurrency && idx < items.length) {
        const i = idx++;
        running++;
        Promise.resolve(fn(items[i], i)).then(
          r => { results[i] = r; running--; done++; if (done === items.length) resolve(results); else step(); },
          reject
        );
      }
    };
    if (items.length === 0) resolve([]);
    else step();
  });
}

(async () => {
  const cfg = loadConfig();
  const crawl = readArtifact('phase7_crawl.json');
  const auth = readArtifact('phase6_auth.json') || { roles: [] };
  if (!crawl) throw new Error('phase7 artifact missing');

  // Unique canonical endpoints
  const endpointSet = new Map();
  for (const e of crawl.endpoints) {
    if (!endpointSet.has(e.canonical)) {
      endpointSet.set(e.canonical, Array.from(new Set(e.methods || ['GET'])));
    } else {
      const existing = endpointSet.get(e.canonical);
      endpointSet.set(e.canonical, Array.from(new Set([...existing, ...(e.methods || [])])));
    }
  }
  const endpoints = Array.from(endpointSet.entries());
  log(8, `${endpoints.length} unique endpoints to probe`);

  const roles = [{ name: 'unauthenticated', stateFile: null }];
  for (const r of auth.roles || []) {
    if (r.success) roles.push({ name: r.role, stateFile: path.join(AUTH_DIR, r.stateFile) });
  }

  const CONCURRENCY = cfg.limits?.classifyConcurrency || 6;
  const TIMEOUT = cfg.limits?.classifyTimeoutMs || 5000;

  const browser = await chromium.launch({ headless: true });
  const matrix = {};
  try {
    for (const role of roles) {
      log(8, `classifying against role=${role.name} (concurrency=${CONCURRENCY}, timeout=${TIMEOUT}ms)`);
      const opts = { ignoreHTTPSErrors: true };
      if (role.stateFile && fs.existsSync(role.stateFile)) opts.storageState = role.stateFile;
      const context = await browser.newContext(opts);

      let completed = 0;
      await parallelMap(endpoints, CONCURRENCY, async ([canonical, methods]) => {
        const concrete = canonical
          .replace(/:id/g, '1')
          .replace(/:uuid/g, '00000000-0000-0000-0000-000000000001')
          .replace(/:hexid/g, '000000000000000000000001');
        const fullUrl = new URL(concrete, cfg.target).toString();
        const method = methods.includes('GET') ? 'GET' : methods[0];
        try {
          const resp = await context.request.fetch(fullUrl, {
            method, timeout: TIMEOUT, maxRedirects: 0, failOnStatusCode: false,
          });
          if (!matrix[canonical]) matrix[canonical] = {};
          matrix[canonical][role.name] = { status: resp.status(), method };
        } catch (err) {
          if (!matrix[canonical]) matrix[canonical] = {};
          matrix[canonical][role.name] = { status: 0, error: err.message.slice(0, 120), method };
        }
        completed++;
        if (completed % 10 === 0 || completed === endpoints.length) {
          log(8, `  ${role.name}: ${completed}/${endpoints.length}`);
        }
      });

      await context.close();
    }
  } finally {
    await browser.close();
  }

  // Anomaly detection: endpoints where access differs between roles in suspicious ways
  const anomalies = [];
  for (const [canonical, perRole] of Object.entries(matrix)) {
    const codes = Object.values(perRole).map(v => v.status);
    const unique = new Set(codes);
    if (unique.size > 1 && unique.has(200)) {
      anomalies.push({ canonical, perRole, note: 'role-dependent access' });
    }
  }

  writeArtifact('phase8_classify.json', {
    phase: 8,
    timestamp: new Date().toISOString(),
    endpointCount: endpoints.length,
    roles: roles.map(r => r.name),
    concurrency: CONCURRENCY,
    timeoutMs: TIMEOUT,
    matrix,
    anomalies,
  });
  log(8, `OK: ${Object.keys(matrix).length} endpoints classified, ${anomalies.length} access anomalies`);
})();
