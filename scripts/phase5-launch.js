// Phase 5: Launch Discovery Agent — records the crawl strategy decision.
// Under the Claude Code skill this is Claude's judgment call. For automated
// runs (runner.js), a deterministic mapping based on phase 4 output stands in.

const { readArtifact, writeArtifact, log } = require('./lib');

(async () => {
  const p1 = readArtifact('phase1_accessibility.json');
  const p2 = readArtifact('phase2_metadata.json');
  const p3 = readArtifact('phase3_fingerprint.json');
  const p4 = readArtifact('phase4_apptype.json');
  if (!p1?.accessible) throw new Error('phase1 says target unreachable — cannot launch');
  if (!p2 || !p3 || !p4) throw new Error('prerequisite artifacts missing');

  const strategy = p4.appType; // SPA / Traditional / Hybrid
  const rationale = {
    SPA: 'SPA detected — use browser automation with networkidle waits and bounded event-firing.',
    Traditional: 'Traditional app — link-following crawl, deeper depth, no event-firing.',
    Hybrid: 'Hybrid — browser automation but conservative event-firing.',
  }[strategy];

  writeArtifact('phase5_launch.json', {
    phase: 5,
    decision: 'proceed',
    strategy,
    rationale,
    validatedInputs: ['phase1', 'phase2', 'phase3', 'phase4'],
    timestamp: new Date().toISOString(),
  });
  log(5, `OK: strategy=${strategy} (${rationale})`);
})();
