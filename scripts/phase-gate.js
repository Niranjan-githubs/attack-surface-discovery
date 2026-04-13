// phase-gate.js — deterministic PASS / WARN / FAIL gate for a phase.
//
// Reads the phase's artifact(s) from output/artifacts/ and emits output/gates/gate{N}.json
// with verdict, blockers, warnings, and brainstorming suggestions for a Quality Reviewer.
//
// Usage: node scripts/phase-gate.js <N>
//
// Deterministic — no LLM. The SKILL instructs Claude to spawn a Quality Reviewer
// subagent AFTER the gate, for the judgment checks the gate can't make.

const fs = require('fs');
const path = require('path');
const { readArtifact, log, ARTIFACTS, OUTPUT } = require('./lib');

const GATES_DIR = path.join(OUTPUT, 'gates');
fs.mkdirSync(GATES_DIR, { recursive: true });

const CHECKS = {
  2: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase2 artifact missing'], warnings, brainstorm };
    if ((a.initialEndpoints || []).length < 3 && !a.htmlBodyEmpty) warnings.push('Fewer than 3 initial endpoints on a non-SPA page — the homepage may be behind auth or a WAF.');
    if ((a.techStack?.frameworks || []).length === 0 && !a.techStack?.server) warnings.push('No tech stack detected. If target is unusual, add hints to config.');
    if (a.htmlBodyEmpty && (a.scripts || []).length === 0) blockers.push('Empty body AND no scripts — page may have failed to render. Re-run with browser-based fetch.');
    brainstorm.push('Check if phase 2 caught <meta name="csrf-token"> — if yes, note it for phase 14.');
    brainstorm.push('Inspect discovered scripts — any minified vendor bundles worth adding to phase 11?');
    return { blockers, warnings, brainstorm };
  },
  3: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase3 artifact missing'], warnings, brainstorm };
    if (!a.hasConsistent404) warnings.push('Inconsistent 404 pattern — phase 10 fuzzing results will be less reliable.');
    if (a.soft404Warning) warnings.push('Soft-404 detected: target returns 200 for nonsense paths. Phase 10 relies on body-length comparison.');
    if ((a.samples || []).some(s => s.error)) warnings.push('Some fingerprint probes errored — target may throttle probe bursts.');
    return { blockers, warnings, brainstorm };
  },
  4: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase4 artifact missing'], warnings, brainstorm };
    if (a.confidence < 0.6) warnings.push(`App-type confidence ${a.confidence} is low. Phase 7 will treat as Hybrid — verify by eyeballing phase 2 scripts.`);
    return { blockers, warnings, brainstorm };
  },
  5: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase5 launch decision missing'], warnings, brainstorm };
    if (a.decision !== 'proceed') blockers.push(`Launch decision was "${a.decision}" — do not start phase 6.`);
    return { blockers, warnings, brainstorm };
  },
  6: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase6 artifact missing'], warnings, brainstorm };
    const roles = a.roles || [];
    const failed = roles.filter(r => !r.success);
    if (roles.length > 0 && failed.length === roles.length) {
      warnings.push(`All ${roles.length} role(s) failed to authenticate. Follow Auth Failure Escalation before proceeding.`);
      brainstorm.push('Can any tests still run unauthenticated? Consult the SKILL "What stays testable" list.');
    } else if (failed.length > 0) {
      warnings.push(`${failed.length}/${roles.length} roles failed to authenticate: ${failed.map(f => f.role).join(', ')}`);
    }
    return { blockers, warnings, brainstorm };
  },
  7: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase7 artifact missing'], warnings, brainstorm };
    const endpoints = a.endpoints || [];
    if (endpoints.length === 0) blockers.push('Phase 7 discovered zero endpoints. Rerun with different strategy.');
    else if (endpoints.length < 5) warnings.push(`Only ${endpoints.length} endpoints crawled — app may be tiny, blocked, or behind auth.`);
    const traffic = readArtifact('phase13_traffic.json');
    if (!traffic || (traffic.requests || []).length === 0) warnings.push('Phase 13 traffic artifact is empty. Route interception may have failed.');
    brainstorm.push('Are there roles that had dramatically fewer endpoints than others? That is a finding.');
    return { blockers, warnings, brainstorm };
  },
  8: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase8 artifact missing'], warnings, brainstorm };
    if (!a.matrix || Object.keys(a.matrix).length === 0) blockers.push('Empty classification matrix.');
    if ((a.anomalies || []).length > 0) brainstorm.push(`${a.anomalies.length} role-access anomalies detected — surface these in the report anomalies section.`);
    return { blockers, warnings, brainstorm };
  },
  9: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase9 artifact missing'], warnings, brainstorm };
    if (a.error) warnings.push(`Wayback query error: ${a.error}`);
    if ((a.stillLive || []).length > 0) brainstorm.push(`${a.stillLive.length} historical endpoints still respond — note any that look deprecated.`);
    return { blockers, warnings, brainstorm };
  },
  10: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase10 artifact missing'], warnings, brainstorm };
    if ((a.candidatesTested || 0) < 30) warnings.push(`Only ${a.candidatesTested} fuzz candidates tested — LLM predictions may not have been supplied.`);
    if ((a.hits || []).length === 0 && (a.authProtected || []).length === 0) warnings.push('Fuzzing found nothing. Either coverage is already exhaustive or the baseline 404 fingerprint is weak.');
    return { blockers, warnings, brainstorm };
  },
  11: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase11 artifact missing'], warnings, brainstorm };
    if ((a.filesAnalyzed || 0) === 0) warnings.push('No JS files analyzed. Either the target is server-rendered or phase 7 did not capture script URLs.');
    if ((a.secrets || []).length > 0) brainstorm.push(`${a.secrets.length} secrets flagged — ensure each is listed in the report JS Analysis section with severity.`);
    return { blockers, warnings, brainstorm };
  },
  12: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase12 artifact missing'], warnings, brainstorm };
    if (a.graphqlFound && !a.graphqlSchema) warnings.push('GraphQL endpoint exists but introspection was disabled — flag as limitation.');
    return { blockers, warnings, brainstorm };
  },
  13: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase13 artifact missing (phase 7 did not route-intercept)'], warnings, brainstorm };
    if ((a.requests || []).length === 0) blockers.push('Traffic artifact exists but contains zero requests.');
    return { blockers, warnings, brainstorm };
  },
  14: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase14 artifact missing'], warnings, brainstorm };
    if ((a.coverage || 0) < 0.6) warnings.push(`Parameter classification coverage is ${Math.round(a.coverage * 100)}% — below 60% threshold.`);
    return { blockers, warnings, brainstorm };
  },
  15: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase15 artifact missing'], warnings, brainstorm };
    if ((a.totalEndpoints || 0) === 0) blockers.push('Deduplicated inventory is empty — pipeline catastrophically failed.');
    const srcs = Object.keys(a.bySource || {});
    if (srcs.length < 3) warnings.push(`Only ${srcs.length} discovery sources contributed to inventory. Check if phases 9/10/11/12 ran.`);
    return { blockers, warnings, brainstorm };
  },
  16: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase16 artifact missing'], warnings, brainstorm };
    if ((a.workflows || []).length === 0) warnings.push('No workflows identified — target may be too small to support flow mapping.');
    if ((a.workflows || []).length < 3) warnings.push(`Only ${(a.workflows || []).length} workflows — brief targets 3+ for full credit.`);
    if (a.note && a.note.includes('Heuristic fallback')) brainstorm.push('Heuristic flow mapping was used — Claude-orchestrated pass would name workflows better.');
    return { blockers, warnings, brainstorm };
  },
  17: (a) => {
    const blockers = [], warnings = [], brainstorm = [];
    if (!a) return { blockers: ['phase17 artifact missing'], warnings, brainstorm };
    if ((a.rowCounts?.endpoints || 0) === 0) blockers.push('Zero endpoints written to DB.');
    if ((a.rowCounts?.role_access || 0) === 0 && (a.rowCounts?.endpoints || 0) > 0) warnings.push('No role_access rows — phase 8 may have produced nothing or roles were empty.');
    return { blockers, warnings, brainstorm };
  },
};

function verdictOf(blockers, warnings) {
  if (blockers.length > 0) return 'FAIL';
  if (warnings.length > 0) return 'WARN';
  return 'PASS';
}

const N = Number(process.argv[2]);
if (!Number.isFinite(N)) {
  console.error('usage: phase-gate.js <phase-number>');
  process.exit(1);
}

const check = CHECKS[N];
if (!check) {
  // No gate defined for this phase — trivially pass.
  const out = { phase: N, verdict: 'PASS', blockers: [], warnings: [], brainstorm: [], note: 'no gate defined' };
  fs.writeFileSync(path.join(GATES_DIR, `gate${N}.json`), JSON.stringify(out, null, 2));
  process.exit(0);
}

// Find the artifact file for this phase (pattern: phase{N}_*.json)
const files = fs.readdirSync(ARTIFACTS).filter(f => f.startsWith(`phase${N}_`) && f.endsWith('.json'));
const primary = files.length ? readArtifact(files[0]) : null;

const { blockers, warnings, brainstorm } = check(primary);
const verdict = verdictOf(blockers, warnings);
const out = {
  phase: N,
  timestamp: new Date().toISOString(),
  verdict,
  blockers,
  warnings,
  brainstorm,
  inspectedArtifact: files[0] || null,
};
fs.writeFileSync(path.join(GATES_DIR, `gate${N}.json`), JSON.stringify(out, null, 2));
log('gate', `phase ${N}: ${verdict} (${blockers.length} blockers, ${warnings.length} warnings)`);
if (verdict === 'FAIL') process.exit(2);
