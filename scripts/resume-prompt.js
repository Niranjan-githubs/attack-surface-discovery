// resume-prompt.js — generates output/resume-prompt.md, a self-contained prompt
// a fresh Claude session can paste to pick up an interrupted run.
//
// Called automatically by runner.js after every phase. Can also be called
// manually: node scripts/resume-prompt.js

const fs = require('fs');
const path = require('path');
const { loadConfig, ARTIFACTS, OUTPUT } = require('./lib');

const RESUME_PATH = path.join(OUTPUT, 'resume-prompt.md');

function phasesCompleted() {
  if (!fs.existsSync(ARTIFACTS)) return [];
  const files = fs.readdirSync(ARTIFACTS);
  const nums = new Set();
  for (const f of files) {
    const m = f.match(/^phase(\d+)_/);
    if (m) nums.add(Number(m[1]));
  }
  return Array.from(nums).sort((a, b) => a - b);
}

function gatesStatus() {
  const gatesDir = path.join(OUTPUT, 'gates');
  if (!fs.existsSync(gatesDir)) return {};
  const out = {};
  for (const f of fs.readdirSync(gatesDir)) {
    const m = f.match(/^gate(\d+)\.json$/);
    if (!m) continue;
    const g = JSON.parse(fs.readFileSync(path.join(gatesDir, f), 'utf8'));
    out[m[1]] = g.verdict;
  }
  return out;
}

(function main() {
  let cfg = {};
  try { cfg = loadConfig(); } catch { cfg = { target: '(config.json missing)' }; }
  const done = phasesCompleted();
  const gates = gatesStatus();
  const lastDone = done.length ? Math.max(...done) : 0;
  const nextPhase = lastDone >= 18 ? null : lastDone + 1;

  const md = `# Resume prompt — attack-surface-discovery

_Generated ${new Date().toISOString()}. Paste this into a fresh Claude Code session to continue the run._

## Target and scope

- **Target:** ${cfg.target}
- **Scope domains:** ${JSON.stringify(cfg.scope?.domains || [cfg.target])}
- **Mode:** ${cfg.mode || 'full'}
- **Config:** \`config.json\`
- **Credentials:** \`credentials.json\` ${fs.existsSync(path.join(OUTPUT, '..', 'credentials.json')) ? '(present)' : '(absent — unauthenticated scan)'}

## What's done

Completed phases: ${done.length ? done.join(', ') : '(none yet)'}

Phase gates:
${Object.keys(gates).length ? Object.entries(gates).map(([p, v]) => `- Phase ${p}: **${v}**`).join('\n') : '- (no gates recorded yet)'}

## What to do next

${nextPhase
  ? `1. Read \`SKILL.md\`.\n2. Jump to **Phase ${nextPhase}**. The prior phase artifacts are in \`output/artifacts/\` — read only what you need.\n3. Run the phase script, run \`node scripts/phase-gate.js ${nextPhase}\`, spawn the Quality Reviewer, then continue.\n4. After each phase, this file is refreshed by \`scripts/resume-prompt.js\` — you do not need to run it manually.`
  : `All phases are marked complete. Run the Final Judge (see \`SKILL.md\` "Final Judge") to audit the report before presenting it to the user.`}

## Important reminders

- **Do not re-run completed phases** unless a gate was FAIL. Artifacts are the system of record.
- **Do not delete \`output/\`** between partial runs.
- **Multi-domain scope:** if phase 2 or 6 revealed off-domain redirects, make sure they are in \`config.json\` → \`scope.domains\` before running any more discovery phases.
- **Error tiers:** see SKILL.md "When things go wrong" — Tier 1 retries 3× with short backoff, Tier 2 pauses 30–60s and lowers concurrency, Tier 3 does not retry.

## File map

- \`output/artifacts/phase{N}_*.json\` — phase outputs (system of record)
- \`output/gates/gate{N}.json\` — gate verdicts
- \`output/auth/state-{role}.json\` — per-role Playwright storage states
- \`output/auth/refresh-{role}.js\` — auto-generated refresh scripts
- \`output/storage/reconnaissance.db\` — final SQLite inventory (written at phase 17)
- \`output/reports/report.{json,md}\` — final report (written at phase 18)
- \`output/reports/final-judge.json\` — heuristic Judge verdict
- \`output/logs/orchestrator.log\` — append-only log

## Artifact inventory (current)

${done.length ? done.map(n => {
    const files = fs.readdirSync(ARTIFACTS).filter(f => f.startsWith(`phase${n}_`));
    return files.map(f => `- \`output/artifacts/${f}\``).join('\n');
  }).join('\n') : '- (no artifacts yet)'}
`;

  fs.writeFileSync(RESUME_PATH, md);
})();
