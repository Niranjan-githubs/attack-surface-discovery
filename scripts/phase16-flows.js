// Phase 16: Application Flow Mapping.
// Under the Claude Code skill this is pure LLM work. For automated runs (runner.js),
// this heuristic stand-in groups traffic into likely workflows by burstiness +
// role + common-prefix patterns. Claude would produce richer, better-named flows.

const { readArtifact, writeArtifact, log } = require('./lib');

const FLOW_HEURISTICS = [
  { name: 'Authentication', match: /\b(login|signin|auth|token|register|signup|logout)\b/i, purpose: 'User authentication and session management' },
  { name: 'User profile', match: /\b(me|profile|user|account|settings)\b/i, purpose: 'View or update user profile' },
  { name: 'Product browse', match: /\b(products?|items?|catalog|search)\b/i, purpose: 'Browse or search the product catalog' },
  { name: 'Cart & checkout', match: /\b(cart|basket|checkout|order|payment)\b/i, purpose: 'Add items to cart and complete purchase' },
  { name: 'Admin', match: /\badmin\b/i, purpose: 'Administrative operations' },
  { name: 'Feedback / Support', match: /\b(feedback|contact|support|complaint|help)\b/i, purpose: 'Submit feedback or support requests' },
  { name: 'File handling', match: /\b(upload|download|files?|attachment)\b/i, purpose: 'File upload or retrieval' },
];

(async () => {
  const traffic = readArtifact('phase13_traffic.json');
  if (!traffic) throw new Error('phase13 artifact missing');

  // Bucket requests by heuristic, ordered by timestamp, deduped on path/method.
  const flowBuckets = FLOW_HEURISTICS.map(h => ({ ...h, steps: [] }));
  const seenPerFlow = FLOW_HEURISTICS.map(() => new Set());

  const sorted = [...traffic.requests].sort((a, b) => a.ts - b.ts);
  for (const req of sorted) {
    if (req.resourceType && !['xhr', 'fetch', 'document'].includes(req.resourceType)) continue;
    for (const [i, h] of FLOW_HEURISTICS.entries()) {
      if (h.match.test(req.path)) {
        const key = `${req.method}|${req.path}|${req.role || ''}`;
        if (!seenPerFlow[i].has(key)) {
          seenPerFlow[i].add(key);
          flowBuckets[i].steps.push({
            endpoint: req.path,
            method: req.method,
            role: req.role || 'unauthenticated',
            status: req.status || null,
          });
        }
        break;
      }
    }
  }

  const workflows = flowBuckets
    .filter(f => f.steps.length >= 2)
    .map(f => ({
      name: f.name,
      purpose: f.purpose,
      steps: f.steps.slice(0, 10),
      dependencies: f.name === 'Cart & checkout' ? ['Authentication'] : [],
      source: 'heuristic-default',
    }));

  writeArtifact('phase16_flows.json', {
    phase: 16,
    timestamp: new Date().toISOString(),
    note: 'Heuristic fallback used. Claude-orchestrated runs produce better-named, context-aware flows from the same traffic artifact.',
    workflowCount: workflows.length,
    workflows,
  });
  log(16, `OK: ${workflows.length} workflows identified (heuristic)`);
})();
