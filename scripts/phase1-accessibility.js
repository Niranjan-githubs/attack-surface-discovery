// Phase 1: Target Accessibility Check
// Deterministic — just verify the target responds.
// Sends a request to the target
//  Checks response (status, time, headers)
// Decides: accessible or not
// Saves result
// Stops pipeline if failed

const { loadConfig, writeArtifact, fetchWithTimeout, log } = require('./lib');

(async () => {
  const cfg = loadConfig();
  const target = cfg.target;
  log(1, `checking accessibility of ${target}`);

  const result = {
    phase: 1,
    target,
    timestamp: new Date().toISOString(),
    accessible: false,
    statusCode: null,
    responseTimeMs: null,
    headers: {},
    error: null,
  };

  const start = Date.now();
  try {
    // GET not HEAD — some sites return 405 on HEAD.
    const res = await fetchWithTimeout(target, { method: 'GET', redirect: 'manual' }, 30000);
    result.responseTimeMs = Date.now() - start;
    result.statusCode = res.status;
    result.headers = Object.fromEntries(res.headers.entries());
    // Any non-5xx = reachable. 3xx is fine (means the target is up).
    result.accessible = res.status < 500;
  } catch (err) {
    result.error = err.message;
    result.responseTimeMs = Date.now() - start;
  }

  writeArtifact('phase1_accessibility.json', result);
  if (!result.accessible) {
    log(1, `FAIL: ${result.error || `status ${result.statusCode}`}`);
    process.exit(2);
  }
  log(1, `OK: ${result.statusCode} in ${result.responseTimeMs}ms`);
})();
