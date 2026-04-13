// final-judge.js — heuristic zero-context audit of the final report.
//
// This is the deterministic version used by the automated runner. When Claude
// orchestrates via SKILL.md, the Judge is a zero-context Task subagent — this
// script covers the mechanical checks either way.
//
// Outputs output/reports/final-judge.json with verdict + actions.

const fs = require('fs');
const path = require('path');
const { readArtifact, log, REPORTS_DIR, OUTPUT } = require('./lib');

const GATES_DIR = path.join(OUTPUT, 'gates');

function loadReport() {
  const reportPath = path.join(REPORTS_DIR, 'report.json');
  if (!fs.existsSync(reportPath)) return null;
  return JSON.parse(fs.readFileSync(reportPath, 'utf8'));
}

function loadGates() {
  if (!fs.existsSync(GATES_DIR)) return [];
  return fs.readdirSync(GATES_DIR).sort().map(f =>
    JSON.parse(fs.readFileSync(path.join(GATES_DIR, f), 'utf8'))
  );
}

function check(report, gates) {
  const critical = [];
  const recommended = [];
  const observations = [];

  // Lens 1 — Coverage integrity: did every discovery source contribute?
  const expectedSources = ['active-crawl', 'traffic', 'fuzzing', 'js-analysis', 'api-spec', 'wayback'];
  const gotSources = (report?.totals?.discoverySources || []);
  const missingSources = expectedSources.filter(s =>
    !gotSources.some(g => g === s || g.includes(s.split('-')[0]))
  );
  if (missingSources.length > 2) {
    critical.push({
      action: `Only ${gotSources.length} of 6 discovery sources contributed. Missing: ${missingSources.join(', ')}.`,
      rationale: 'Endpoint Discovery Completeness is 30% of the score — missing sources visibly shrink the inventory.',
      priority: 'HIGH',
    });
  } else if (missingSources.length > 0) {
    recommended.push({
      action: `Missing discovery sources: ${missingSources.join(', ')}. Verify the phases ran and contributed endpoints.`,
      priority: 'MEDIUM',
    });
  }

  // Lens 2 — Role-access consistency.
  const ram = report?.roleAccessMatrix || {};
  const endpointCount = (report?.endpointInventory || []).length;
  const ramCount = Object.keys(ram).length;
  if (endpointCount > 0 && ramCount < endpointCount * 0.5) {
    recommended.push({
      action: `Role-access matrix covers only ${ramCount} of ${endpointCount} endpoints. Phase 8 should probe every endpoint from the inventory.`,
      priority: 'HIGH',
    });
  }
  if ((report?.anomalies || []).length > 0 && !/anomal/i.test(fs.readFileSync(path.join(REPORTS_DIR, 'report.md'), 'utf8'))) {
    critical.push({
      action: `${report.anomalies.length} role-access anomalies detected but not surfaced in report.md.`,
      priority: 'HIGH',
    });
  }

  // Lens 3 — Flow plausibility.
  const flows = report?.workflows || [];
  if (flows.length === 0) {
    recommended.push({
      action: 'Zero workflows identified. If the target is non-trivial, phase 16 needs rerunning.',
      priority: 'MEDIUM',
    });
  } else {
    const stepless = flows.filter(f => (f.steps || []).length < 2);
    if (stepless.length > 0) {
      recommended.push({
        action: `${stepless.length} workflow(s) have <2 steps. A workflow with 1 step is not a workflow.`,
        priority: 'LOW',
      });
    }
  }

  // Lens 4 — Limitations honesty.
  const failedGates = gates.filter(g => g.verdict === 'FAIL');
  const warnGates = gates.filter(g => g.verdict === 'WARN');
  const limitationsText = JSON.stringify(report?.limitations || []);
  if (failedGates.length > 0) {
    const unmentioned = failedGates.filter(g =>
      !g.blockers.some(b => limitationsText.includes(b.slice(0, 20)))
    );
    if (unmentioned.length > 0) {
      critical.push({
        action: `${unmentioned.length} phase(s) hit FAIL gates but the failures are not mentioned in limitations. Phases: ${unmentioned.map(g => g.phase).join(', ')}.`,
        priority: 'HIGH',
      });
    }
  }
  observations.push(`${gates.length} phase gates recorded: ${gates.filter(g => g.verdict === 'PASS').length} PASS, ${warnGates.length} WARN, ${failedGates.length} FAIL.`);

  // Completeness sanity
  const comp = report?.completenessScore || 0;
  if (comp < 0.50) {
    recommended.push({
      action: `Completeness score is ${(comp * 100).toFixed(0)}%. Below 75% target per brief §6.`,
      priority: 'HIGH',
    });
  }
  observations.push(`Completeness score: ${(comp * 100).toFixed(1)}%.`);

  // Secrets handling
  if ((report?.jsAnalysis?.secrets || []).length > 0) {
    observations.push(`${report.jsAnalysis.secrets.length} secret(s) flagged — verify none are exploited, only reported.`);
  }

  // Verdict
  let verdict;
  if (critical.length > 0) verdict = 'FAIL';
  else if (recommended.some(r => r.priority === 'HIGH')) verdict = 'CONDITIONAL_PASS';
  else if (recommended.length > 0) verdict = 'CONDITIONAL_PASS';
  else verdict = 'PASS';

  return { verdict, critical_actions: critical, recommended_actions: recommended, observations };
}

(function main() {
  const report = loadReport();
  const gates = loadGates();
  if (!report) {
    console.error('report.json missing — run phase 18 first.');
    process.exit(1);
  }
  const result = check(report, gates);
  const out = {
    generatedAt: new Date().toISOString(),
    heuristic: true,
    note: 'This is the mechanical Judge. The Claude-orchestrated Judge in SKILL.md runs with zero session context and adds qualitative judgment on top.',
    ...result,
  };
  fs.writeFileSync(path.join(REPORTS_DIR, 'final-judge.json'), JSON.stringify(out, null, 2));
  log('judge', `verdict=${result.verdict} critical=${result.critical_actions.length} recommended=${result.recommended_actions.length}`);
  if (result.verdict === 'FAIL') process.exit(2);
})();
