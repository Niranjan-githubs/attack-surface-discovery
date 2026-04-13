// Phase 3: Baseline Response Fingerprinting
// Hit random paths to characterize how the app signals "not found" / "unauthorized".
// Baseline fingerprinting identifies how a server responds to non-existent endpoints (true 404 behavior).
//  It helps distinguish real endpoints vs hidden ones even if they return the same status code.
//  This is crucial for accurate fuzzing and detecting access control or hidden resource

const crypto = require('crypto');
const { loadConfig, writeArtifact, fetchWithTimeout, log } = require('./lib');

function snippet(body, n = 200) {
  return body.replace(/\s+/g, ' ').trim().slice(0, n);
}

(async () => {
  const cfg = loadConfig();
  const target = cfg.target.replace(/\/$/, '');
  log(3, `fingerprinting error responses`);

  const patterns = {};
  const samples = [];

  // 8 random paths + a few suspicious ones
  const paths = [];
  for (let i = 0; i < 6; i++) {
    paths.push(`/nonexistent-${crypto.randomBytes(6).toString('hex')}.html`);
  }
  paths.push('/admin', '/login', '/.env', '/api/internal-does-not-exist');

  for (const p of paths) {
    try {
      const res = await fetchWithTimeout(target + p, { method: 'GET', redirect: 'manual' }, 10000);
      const body = await res.text();
      const sample = {
        path: p,
        statusCode: res.status,
        contentType: res.headers.get('content-type') || null,
        bodyLength: body.length,
        bodySnippet: snippet(body),
      };
      samples.push(sample);

      const key = String(res.status);
      if (!patterns[key]) {
        patterns[key] = {
          statusCode: res.status,
          samples: [],
          typicalBodyLength: body.length,
          typicalSnippet: snippet(body),
        };
      }
      patterns[key].samples.push(p);
    } catch (err) {
      samples.push({ path: p, error: err.message });
    }
  }

  // Detect "soft 404" — server returns 200 on nonsense paths.
  const randomOnly = samples.filter(s => s.path.startsWith('/nonexistent-'));
  const soft404 = randomOnly.length > 0 && randomOnly.every(s => s.statusCode === 200);

  const result = {
    phase: 3,
    target,
    timestamp: new Date().toISOString(),
    patterns,
    samples,
    soft404Warning: soft404,
    hasConsistent404: !!patterns['404'] && patterns['404'].samples.length >= 3,
  };

  writeArtifact('phase3_fingerprint.json', result);
  log(3, `OK: status codes seen=${Object.keys(patterns).join(',')} soft404=${soft404}`);
})();
