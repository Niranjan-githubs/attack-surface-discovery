// Phase 7: Active Endpoint Crawling.
// Also writes phase13_traffic.json as a side effect via Playwright route interception.

const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');
const {
  loadConfig, readArtifact, writeArtifact, log,
  AUTH_DIR, isInScope, avoidReason, canonicalizePath,
} = require('./lib');

const MAX_PAGES_PER_ROLE = 40;
const MAX_DEPTH = 5;

function parseArgs() {
  const args = {};
  for (const a of process.argv.slice(2)) {
    const m = a.match(/^--([^=]+)=(.*)$/);
    if (m) args[m[1]] = m[2];
  }
  return args;
}

async function crawlOneRole(browser, cfg, strategy, stateFile, roleName) {
  const target = cfg.target;
  const contextOpts = { ignoreHTTPSErrors: true };
  if (stateFile && fs.existsSync(stateFile)) {
    contextOpts.storageState = stateFile;
  }
  const context = await browser.newContext(contextOpts);

  // Traffic interception — captures EVERY request, including XHR. This is phase 13.
  const traffic = [];
  const endpointsSeen = new Map(); // canonical path -> { methods: Set, fromRole, firstSeen }

  context.on('request', req => {
    const url = req.url();
    if (!isInScope(cfg, url)) return;
    const method = req.method();
    traffic.push({
      url,
      path: canonicalizePath(url),
      method,
      resourceType: req.resourceType(),
      headers: req.headers(),
      postData: req.postData() || null,
      role: roleName,
      ts: Date.now(),
    });
    const cp = canonicalizePath(url);
    if (!endpointsSeen.has(cp)) endpointsSeen.set(cp, { methods: new Set(), role: roleName });
    endpointsSeen.get(cp).methods.add(method);
  });

  context.on('response', async res => {
    // Attach status to the last traffic entry for this URL+method (cheap correlation)
    try {
      const req = res.request();
      const url = req.url();
      if (!isInScope(cfg, url)) return;
      for (let i = traffic.length - 1; i >= 0 && i > traffic.length - 200; i--) {
        if (traffic[i].url === url && traffic[i].method === req.method() && !traffic[i].status) {
          traffic[i].status = res.status();
          traffic[i].contentType = res.headers()['content-type'] || null;
          break;
        }
      }
    } catch {}
  });

  const page = await context.newPage();
  const visited = new Set();
  const queue = [{ url: target, depth: 0 }];

  let pagesVisited = 0;
  while (queue.length && pagesVisited < MAX_PAGES_PER_ROLE) {
    const { url, depth } = queue.shift();
    const cp = canonicalizePath(url);
    if (visited.has(cp)) continue;
    visited.add(cp);

    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });
      if (strategy === 'SPA' || strategy === 'Hybrid') {
        // Give XHR/fetch time to settle
        await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});
      }
      pagesVisited++;

      if (depth < MAX_DEPTH) {
        // Collect links
        const hrefs = await page.$$eval('a[href]', els => els.map(e => e.href));
        for (const href of hrefs) {
          if (!isInScope(cfg, href)) continue;
          if (avoidReason(cfg, href)) continue;
          const canon = canonicalizePath(href);
          if (!visited.has(canon)) {
            queue.push({ url: href, depth: depth + 1 });
          }
        }
        // For SPAs: try clicking buttons that look like nav (bounded)
        if (strategy === 'SPA' || strategy === 'Hybrid') {
          const buttons = await page.$$('[role="button"], button:not([type="submit"])');
          for (const btn of buttons.slice(0, 5)) {
            try {
              await btn.click({ timeout: 1000, trial: false });
              await page.waitForLoadState('networkidle', { timeout: 2000 }).catch(() => {});
            } catch {}
          }
        }
      }
    } catch (err) {
      // Navigation can fail on non-navigable URLs (downloads, etc.) — skip
    }
  }

  await context.close();

  const endpoints = Array.from(endpointsSeen.entries()).map(([canonical, v]) => ({
    canonical,
    methods: Array.from(v.methods),
    discoveredBy: 'active-crawl',
    role: v.role,
  }));

  return { role: roleName, pagesVisited, endpoints, traffic };
}

(async () => {
  const args = parseArgs();
  const cfg = loadConfig();
  const auth = readArtifact('phase6_auth.json') || { roles: [] };
  const apptype = readArtifact('phase4_apptype.json');
  const strategy = args.strategy || apptype?.appType || 'Hybrid';
  log(7, `strategy=${strategy}`);

  const browser = await chromium.launch({ headless: true });

  // Always do an unauth pass
  const passes = [{ role: 'unauthenticated', stateFile: null }];
  for (const r of auth.roles || []) {
    if (r.success) {
      passes.push({ role: r.role, stateFile: path.join(AUTH_DIR, r.stateFile) });
    }
  }

  const allEndpoints = [];
  const allTraffic = [];
  try {
    for (const p of passes) {
      log(7, `crawling as ${p.role}`);
      const r = await crawlOneRole(browser, cfg, strategy, p.stateFile, p.role);
      log(7, `  → ${p.role}: ${r.pagesVisited} pages, ${r.endpoints.length} endpoints, ${r.traffic.length} requests`);
      allEndpoints.push(...r.endpoints);
      allTraffic.push(...r.traffic);
    }
  } finally {
    await browser.close();
  }

  writeArtifact('phase7_crawl.json', {
    phase: 7,
    strategy,
    timestamp: new Date().toISOString(),
    endpoints: allEndpoints,
    rolesCrawled: passes.map(p => p.role),
  });
  writeArtifact('phase13_traffic.json', {
    phase: 13,
    timestamp: new Date().toISOString(),
    requestCount: allTraffic.length,
    requests: allTraffic,
  });

  log(7, `OK: ${allEndpoints.length} endpoint observations, ${allTraffic.length} requests captured`);
})();
