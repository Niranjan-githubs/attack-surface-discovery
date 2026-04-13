// runner.js — end-to-end automated harness.
//
// NOT the orchestrator — SKILL.md is. This is a CI-friendly harness that runs
// every phase + its gate + the resume-prompt refresh, then the final judge.

const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const { loadConfig } = require('./lib');

const SCRIPT_DIR = __dirname;
const OUTPUT_DIR = path.join(SCRIPT_DIR, '..', 'output');

// [phaseNum, scriptFile, runGate, isCritical]
const PHASES = [
  ['1',  'phase1-accessibility.js',  false, true],   // no gate — if it passes we proceed; fail = abort
  ['2',  'phase2-metadata.js',       true,  false],
  ['3',  'phase3-fingerprint.js',    true,  false],
  ['4',  'phase4-apptype.js',        true,  false],
  ['5',  'phase5-launch.js',         true,  true],   // blocker = stop
  ['6',  'phase6-auth.js',           true,  false],
  ['7',  'phase7-crawl.js',          true,  false],
  ['8',  'phase8-classify.js',       true,  false],
  ['9',  'phase9-wayback.js',        true,  false],
  ['11', 'phase11-js.js',            true,  false],
  ['12', 'phase12-apidocs.js',       true,  false],
  ['10', 'phase10-fuzz.js',          true,  false],
  ['13', null,                       true,  false],  // no standalone script — captured in phase 7
  ['14', 'phase14-params.js',        true,  false],
  ['15', 'phase15-dedup.js',         true,  false],
  ['16', 'phase16-flows.js',         true,  false],
  ['17', 'phase17-storage.js',       true,  false],
  ['18', 'phase18-report.js',        false, false],  // report itself
];

function run(script) {
  const full = path.join(SCRIPT_DIR, script);
  if (!fs.existsSync(full)) return { status: 'missing' };
  const start = Date.now();
  const r = spawnSync(process.execPath, [full], { stdio: 'inherit' });
  return { status: r.status, durationMs: Date.now() - start };
}

let cfg;
try { cfg = loadConfig(); }
catch (e) { console.error(`config.json load failed: ${e.message}`); process.exit(1); }

console.log(`\n═══ attack-surface-discovery run against ${cfg.target} (mode=${cfg.mode || 'full'}) ═══`);

const results = [];

for (const [num, script, runGate, isCritical] of PHASES) {
  if (script) {
    console.log(`\n─── Phase ${num}: ${script} ───`);
    const r = run(script);
    if (r.status === 'missing') {
      console.error(`[runner] missing: ${script}`);
      results.push({ phase: num, status: 'missing' });
      continue;
    }
    if (num === '1' && r.status === 2) {
      console.error('[runner] target unreachable — aborting');
      results.push({ phase: num, status: 'fail-fatal' });
      break;
    }
    if (r.status !== 0) {
      console.error(`[runner] phase ${num} exited ${r.status}`);
      results.push({ phase: num, status: 'fail', exitCode: r.status, durationMs: r.durationMs });
      if (isCritical) break;
      continue;
    }
    results.push({ phase: num, status: 'completed', durationMs: r.durationMs });
  } else {
    console.log(`\n─── Phase ${num}: (no standalone script — artifact captured earlier) ───`);
  }

  if (runGate) {
    const g = spawnSync(process.execPath, [path.join(SCRIPT_DIR, 'phase-gate.js'), num], { stdio: 'inherit' });
    if (g.status === 2) {
      console.error(`[runner] gate${num} FAIL`);
      results.push({ phase: `${num}-gate`, status: 'fail' });
      if (isCritical) break;
    }
  }

  // Refresh resume prompt after every phase
  spawnSync(process.execPath, [path.join(SCRIPT_DIR, 'resume-prompt.js')], { stdio: 'ignore' });
}

// Final Judge — heuristic version. Then rerun phase 18 so its embedded
// "Final Judge Verdict" section reflects this run, not a stale prior one.
console.log('\n─── Final Judge ───');
const judgeRes = spawnSync(process.execPath, [path.join(SCRIPT_DIR, 'final-judge.js')], { stdio: 'inherit' });
results.push({ phase: 'final-judge', status: judgeRes.status === 0 ? 'PASS' : (judgeRes.status === 2 ? 'FAIL' : 'CONDITIONAL_PASS') });

console.log('\n─── Phase 18 (re-run to embed Judge verdict) ───');
spawnSync(process.execPath, [path.join(SCRIPT_DIR, 'phase18-report.js')], { stdio: 'inherit' });

fs.writeFileSync(
  path.join(OUTPUT_DIR, 'run-summary.json'),
  JSON.stringify({ completedAt: new Date().toISOString(), target: cfg.target, mode: cfg.mode || 'full', results }, null, 2)
);

console.log('\n═══ Run complete ═══');
const summary = results.reduce((a, r) => ({ ...a, [r.status]: (a[r.status] || 0) + 1 }), {});
console.log(JSON.stringify(summary, null, 2));
console.log(`\nReport: output/reports/report.md`);
console.log(`Resume prompt: output/resume-prompt.md`);
console.log(`Judge verdict: output/reports/final-judge.json`);
