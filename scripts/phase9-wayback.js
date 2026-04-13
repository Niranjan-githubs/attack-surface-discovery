// Phase 9: Historical Endpoint Retrieval via Wayback Machine CDX API.

const { URL } = require('url');
const { loadConfig, writeArtifact, fetchWithTimeout, log, canonicalizePath } = require('./lib');

(async () => {
  const cfg = loadConfig();
  const u = new URL(cfg.target);
  const host = u.hostname;
  log(9, `querying Wayback CDX for ${host}`);

  // CDX API — returns distinct URLs historically captured
  const cdxUrl = `http://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(host + '/*')}&output=json&fl=original,statuscode,timestamp&collapse=urlkey&limit=500`;

  const result = {
    phase: 9,
    target: cfg.target,
    timestamp: new Date().toISOString(),
    historicalUrls: [],
    stillLive: [],
    error: null,
  };

  try {
    const res = await fetchWithTimeout(cdxUrl, {}, 60000);
    if (!res.ok) throw new Error(`CDX returned ${res.status}`);
    const rows = await res.json();
    // First row is header
    const data = rows.slice(1).map(r => ({ url: r[0], archivedStatus: r[1], timestamp: r[2] }));
    // Dedupe by canonical path
    const seen = new Set();
    for (const d of data) {
      try {
        const p = new URL(d.url).pathname;
        const c = canonicalizePath(p);
        if (seen.has(c)) continue;
        seen.add(c);
        result.historicalUrls.push({ ...d, path: p, canonical: c });
      } catch {}
    }
    log(9, `retrieved ${result.historicalUrls.length} unique historical paths`);

    // Probe first 50 against the live target to see which still respond
    const probe = result.historicalUrls.slice(0, 50);
    for (const h of probe) {
      const live = new URL(h.path, cfg.target).toString();
      try {
        const r = await fetchWithTimeout(live, { method: 'HEAD' }, 8000);
        if (r.status < 500 && r.status !== 404) {
          result.stillLive.push({ path: h.path, status: r.status });
        }
      } catch {}
    }
  } catch (err) {
    result.error = err.message;
  }

  writeArtifact('phase9_historical.json', result);
  log(9, `OK: ${result.historicalUrls.length} historical, ${result.stillLive.length} still live`);
})();
