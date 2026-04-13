// Phase 4: Application Type Detection — SPA / Traditional / Hybrid.

const { loadConfig, readArtifact, writeArtifact, log } = require('./lib');

(async () => {
  loadConfig();
  const meta = readArtifact('phase2_metadata.json');
  if (!meta) throw new Error('phase2 artifact missing');

  const signals = {
    emptyBody: meta.htmlBodyEmpty,
    scriptCount: meta.scripts.length,
    frameworks: meta.techStack.frameworks,
    hasSpaFramework: meta.techStack.frameworks.some(f => ['Angular', 'React', 'Vue', 'Next.js', 'Svelte'].includes(f)),
    hasServerForm: meta.techStack.frameworks.includes('server-rendered-form'),
    linkCount: meta.initialEndpoints.length,
    formCount: meta.initialForms.length,
  };

  let appType = 'Traditional';
  let confidence = 0.5;
  let rationale = 'default (no strong signals)';

  if (signals.hasSpaFramework && signals.emptyBody) {
    appType = 'SPA';
    confidence = 0.95;
    rationale = 'SPA framework detected + empty body shell';
  } else if (signals.hasSpaFramework && signals.linkCount < 3) {
    appType = 'SPA';
    confidence = 0.85;
    rationale = 'SPA framework detected + few static links';
  } else if (signals.hasSpaFramework && signals.hasServerForm) {
    appType = 'Hybrid';
    confidence = 0.75;
    rationale = 'SPA framework + server-rendered form(s)';
  } else if (signals.hasSpaFramework) {
    appType = 'Hybrid';
    confidence = 0.65;
    rationale = 'SPA framework but with meaningful initial HTML';
  } else if (signals.linkCount >= 5 && signals.formCount >= 1) {
    appType = 'Traditional';
    confidence = 0.85;
    rationale = 'server-rendered HTML with forms and many links';
  }

  const result = {
    phase: 4,
    appType,
    confidence,
    rationale,
    signals,
    timestamp: new Date().toISOString(),
  };

  writeArtifact('phase4_apptype.json', result);
  log(4, `OK: ${appType} (${confidence}) — ${rationale}`);
})();
