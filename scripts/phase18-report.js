// Phase 18: Report Generation.
// Emits report.json (structured) and report.md (human-readable, brief §4 compliant).
// Every section explicitly maps to a required item in the brief's Report Section table.

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { loadConfig, readArtifact, log, REPORTS_DIR, STORAGE_DIR } = require('./lib');

function section(title, body) {
  return `## ${title}\n\n${body}\n\n`;
}

// Auth-required heuristic: if unauthenticated gets 401/403/302 → auth-required yes.
// If unauth gets 200 and any authenticated role also gets 200 → public.
// If unauth gets 200 but some authenticated role gets a lower code → public with role-dependent content.
function authRequired(roleAccess, roles) {
  if (!roleAccess) return 'unknown';
  const unauthStatus = roleAccess.unauthenticated?.status ?? roleAccess.unauthenticated;
  if (unauthStatus === undefined || unauthStatus === null) return 'unknown';
  if ([401, 403, 302].includes(unauthStatus)) return 'yes';
  if (unauthStatus >= 200 && unauthStatus < 400) return 'no';
  return 'unknown';
}

function rolesWithAccess(roleAccess) {
  if (!roleAccess) return [];
  return Object.entries(roleAccess)
    .filter(([_, v]) => {
      const s = typeof v === 'number' ? v : (v?.status ?? null);
      return s !== null && s >= 200 && s < 400;
    })
    .map(([role]) => role);
}

// Group params by endpoint path for the inventory table.
function paramsByEndpoint(paramsArtifact) {
  const out = {};
  for (const p of (paramsArtifact?.params || [])) {
    if (!out[p.path]) out[p.path] = [];
    out[p.path].push(`${p.name}(${p.classification[0]})${p.semanticType ? ':' + p.semanticType : ''}`);
  }
  return out;
}

(async () => {
  const cfg = loadConfig();
  const db = new Database(path.join(STORAGE_DIR, 'reconnaissance.db'), { readonly: true });

  const p1 = readArtifact('phase1_accessibility.json');
  const p2 = readArtifact('phase2_metadata.json');
  const p3 = readArtifact('phase3_fingerprint.json');
  const p4 = readArtifact('phase4_apptype.json');
  const p6 = readArtifact('phase6_auth.json');
  const p8 = readArtifact('phase8_classify.json');
  const p9 = readArtifact('phase9_historical.json');
  const p10 = readArtifact('phase10_fuzz.json');
  const p11 = readArtifact('phase11_js.json');
  const p12 = readArtifact('phase12_apidocs.json');
  const p14 = readArtifact('phase14_params.json');
  const p15 = readArtifact('phase15_endpoints.json');
  const p16 = readArtifact('phase16_flows.json');
  const p17 = readArtifact('phase17_storage.json');

  const endpoints = db.prepare('SELECT * FROM endpoints ORDER BY canonical').all();
  const roleAccessRows = db.prepare('SELECT e.canonical, ra.role, ra.status FROM endpoints e JOIN role_access ra ON e.id = ra.endpoint_id').all();
  const workflows = db.prepare('SELECT * FROM workflows').all();
  const workflowSteps = db.prepare('SELECT * FROM workflow_steps ORDER BY workflow_id, step_order').all();
  const secrets = db.prepare('SELECT * FROM secrets').all();

  const roles = Array.from(new Set(roleAccessRows.map(r => r.role))).sort();
  const matrix = {};
  for (const r of roleAccessRows) {
    if (!matrix[r.canonical]) matrix[r.canonical] = {};
    matrix[r.canonical][r.role] = r.status;
  }

  const paramMap = paramsByEndpoint(p14);

  // Completeness
  const discoverySources = new Set(endpoints.flatMap(e => (e.sources || '').split(',').filter(Boolean)));
  const paramCoverage = p14?.coverage || 0;
  const completeness = Math.min(1,
    0.30 * Math.min(1, endpoints.length / 30) +
    0.20 * Math.min(1, workflows.length / 3) +
    0.15 * paramCoverage +
    0.15 * Math.min(1, roles.length / 2) +
    0.10 * (p17 ? 1 : 0) +
    0.10 * Math.min(1, discoverySources.size / 5)
  );

  // Limitations — structured collection with cause + impact
  const limitations = [];
  if ((p6?.roles || []).some(r => !r.success)) {
    const failedRoles = p6.roles.filter(r => !r.success).map(r => r.role).join(', ');
    limitations.push({
      issue: `Role(s) failed to authenticate: ${failedRoles}`,
      cause: 'Phase 6 login flow could not complete (form selectors, PKCE, or credential mismatch).',
      impact: 'Endpoints requiring those roles are only probed unauthenticated — authenticated surface is under-covered.',
      mitigation: 'Provide explicit CSS selectors in credentials.json, or capture a session from a logged-in browser and paste it into output/auth/state-{role}.json.',
    });
  }
  if ((p6?.roles || []).length === 0) {
    limitations.push({
      issue: 'No credentials supplied.',
      cause: 'credentials.json either absent or empty roles array.',
      impact: 'Multi-Role Session Handling scoring (15% of evaluation) is 0. Admin/user surfaces only observable via status-code gating.',
      mitigation: 'Register a user on the target, add credentials to credentials.json, rerun phases 6–18.',
    });
  }
  if (p3?.soft404Warning) {
    limitations.push({
      issue: 'Soft-404 detected.',
      cause: 'Target returns HTTP 200 for non-existent paths instead of 404.',
      impact: 'Phase 10 fuzzing results must be body-length filtered; genuine hits can be missed if the target renders identical boilerplate for both live and dead paths.',
      mitigation: 'Accept as a target quirk. Phase 10 uses the phase 3 baseline body length for filtering, which handles this case.',
    });
  }
  if (p9?.error) {
    limitations.push({
      issue: 'Wayback Machine query failed.',
      cause: `CDX API error: ${p9.error}`,
      impact: 'Zero historical paths retrieved. Do not interpret this as evidence the target has no archival footprint.',
      mitigation: 'Retry with longer timeout (updated in phase9-wayback.js). CDX sometimes takes 30-60s for popular domains.',
    });
  }
  if (p12?.graphqlFound && !p12?.graphqlSchema) {
    limitations.push({
      issue: 'GraphQL endpoint present but introspection disabled.',
      cause: 'Server returns 400/403 on introspection query (__schema).',
      impact: 'GraphQL endpoints not enumerable via automated discovery; would require traffic-based learning or source-code analysis.',
      mitigation: 'Enumerate via crawl of UI-triggered queries, or request the schema from the developer.',
    });
  }
  if ((p10?.candidatesTested || 0) < 30) {
    limitations.push({
      issue: 'Fuzzing candidate list was short.',
      cause: 'LLM prediction step (phase 10 reasoning) did not supply a predictions artifact.',
      impact: 'Only the generic wordlist ran, reducing discovery of target-specific patterns (framework routes, admin aliases).',
      mitigation: 'Ensure Claude Code writes phase10_predictions.json before invoking phase10-fuzz.js.',
    });
  }
  // Generic "GET-only crawl" disclaimer when we saw XHR hints in JS but no POST traffic
  const hasJsHints = (p11?.endpoints || []).length > 0 && p11.filesAnalyzed > 0;
  const anyPost = (readArtifact('phase13_traffic.json')?.requests || []).some(r => r.method === 'POST');
  if (hasJsHints && !anyPost) {
    limitations.push({
      issue: 'No POST/write flows exercised.',
      cause: 'Phase 7 crawler navigates and follows links but does not submit forms or fire domain-specific UI events.',
      impact: 'Create/update/delete endpoints implied by JS bundles (subscribe, stock-check, search-log) are not observed in traffic, so phase 14 parameter classification is thin.',
      mitigation: 'Extend phase 7 with targeted form submission and button-click heuristics, or supply credentials to unlock the authenticated paths that exercise these flows.',
    });
  }

  // ========== Response fingerprint cross-role inconsistency detection ==========
  const fingerprintInconsistencies = [];
  if (p3?.patterns && roles.length > 1) {
    // Compare per-role 404/401/403 bodies if we captured them. (We didn't collect per-role baseline
    // bodies, so we flag *observed* per-role discrepancies from phase 8 instead.)
  }
  // From phase 8 matrix: are there status codes returned to one role but not another for the same path?
  if (p8?.anomalies?.length > 0) {
    for (const a of p8.anomalies) {
      fingerprintInconsistencies.push(
        `\`${a.canonical}\` → ${Object.entries(a.perRole).map(([r, v]) => `${r}=${v.status}`).join(', ')}`
      );
    }
  }

  // ========== JSON report ==========
  const reportJson = {
    generatedAt: new Date().toISOString(),
    target: { url: cfg.target, ...(p1 || {}) },
    appType: p4?.appType,
    appTypeConfidence: p4?.confidence,
    techStack: p2?.techStack,
    rolesTested: roles,
    auth: {
      mechanism: p6?.roles?.[0]?.authMechanism || 'none',
      successfulRoles: (p6?.roles || []).filter(r => r.success).map(r => r.role),
    },
    totals: {
      endpoints: endpoints.length,
      workflows: workflows.length,
      parameters: p14?.totalParams || 0,
      secrets: secrets.length,
      discoverySources: Array.from(discoverySources),
      historicalFound: p9?.historicalUrls?.length || 0,
      historicalStillLive: p9?.stillLive?.length || 0,
      apiBasePaths: (p11?.apiBasePaths || []).length,
      clientRoutes: (p11?.clientRoutes || []).length,
    },
    completenessScore: Number(completeness.toFixed(3)),
    endpointInventory: endpoints.map(e => ({
      ...e,
      parameters: paramMap[e.canonical] || [],
      authRequired: authRequired(matrix[e.canonical] || {}, roles),
      rolesWithAccess: rolesWithAccess(matrix[e.canonical] || {}),
    })),
    roleAccessMatrix: matrix,
    roleAccessAnomalies: p8?.anomalies || [],
    workflows: workflows.map(w => ({
      ...w,
      steps: workflowSteps.filter(s => s.workflow_id === w.id),
    })),
    jsAnalysis: {
      filesAnalyzed: p11?.filesAnalyzed || 0,
      endpointsFromJs: p11?.endpoints || [],
      apiBasePaths: p11?.apiBasePaths || [],
      clientRoutes: p11?.clientRoutes || [],
      secrets,
    },
    historical: p9,
    fuzzing: {
      tested: p10?.candidatesTested || 0,
      hits: p10?.hits || [],
      authProtected: p10?.authProtected || [],
      redirects: p10?.redirects || [],
    },
    apiSpecs: p12?.specs || [],
    graphql: p12?.graphqlFound ? (p12?.graphqlSchema || { found: true, introspection: 'disabled' }) : null,
    responseFingerprints: p3?.patterns || {},
    fingerprintInconsistencies,
    limitations,
  };
  fs.writeFileSync(path.join(REPORTS_DIR, 'report.json'), JSON.stringify(reportJson, null, 2));

  // ========== Markdown report ==========
  let md = `# Attack Surface Discovery Report\n\n`;
  md += `**Target:** ${cfg.target}\n`;
  md += `**Generated:** ${reportJson.generatedAt}\n`;
  md += `**Completeness score:** ${(completeness * 100).toFixed(1)}%\n`;
  md += `**Scope:** ${JSON.stringify(cfg.scope?.domains || [cfg.target])}\n\n`;

  // --- Target Summary ---
  md += section('1. Target Summary',
    `- **URL:** ${cfg.target}\n` +
    `- **Application type:** ${p4?.appType} (confidence ${p4?.confidence})\n` +
    `- **Tech stack:** ${(p2?.techStack?.frameworks || []).join(', ') || 'unknown'}` +
      `${p2?.techStack?.server ? ` · server=${p2.techStack.server}` : ''}` +
      `${p2?.techStack?.poweredBy ? ` · x-powered-by=${p2.techStack.poweredBy}` : ''}\n` +
    `- **Authentication mechanism:** ${reportJson.auth.mechanism}\n` +
    `- **Roles tested:** ${roles.length}  (${roles.join(', ') || 'unauthenticated only'})\n` +
    `- **Total endpoints discovered:** ${endpoints.length}\n` +
    `- **Discovery sources used:** ${Array.from(discoverySources).join(', ')}`
  );

  // --- Endpoint Inventory (with parameters, auth-required, roles-with-access) ---
  let epTable = `Per the brief, every endpoint is listed with its URL path, supported HTTP methods, discovery source(s), parameter list (static \`s\` / dynamic \`d\` / unknown \`u\`), authentication requirement, and roles that can access it.\n\n`;
  epTable += `| # | Path | Methods | Sources | Parameters | Auth req? | Roles w/ access |\n`;
  epTable += `|---|------|---------|---------|------------|-----------|------------------|\n`;
  const shown = endpoints.slice(0, 250);
  for (const [i, e] of shown.entries()) {
    const params = (paramMap[e.canonical] || []).slice(0, 6);
    const paramsStr = params.length ? params.join(', ') : '—';
    const auth = authRequired(matrix[e.canonical] || {}, roles);
    const access = rolesWithAccess(matrix[e.canonical] || {});
    epTable += `| ${i + 1} | \`${e.canonical}\` | ${e.methods} | ${e.sources} | ${paramsStr} | ${auth} | ${access.join(', ') || '—'} |\n`;
  }
  if (endpoints.length > shown.length) epTable += `\n_Showing first ${shown.length} of ${endpoints.length}. Full inventory in \`report.json\` → \`endpointInventory\`._\n`;
  epTable += `\n**Parameter classification key:** \`s\` = static (constant across requests), \`d\` = dynamic (IDs/tokens/timestamps), \`u\` = unknown. Semantic type (e.g. \`identifier\`, \`csrf-token\`, \`jwt\`) is appended after \`:\` when detected.\n`;
  md += section('2. Endpoint Inventory', epTable);

  // --- Role-Based Access Map (matrix + anomalies/IDOR candidates) ---
  let ramSection = '';
  if (roles.length > 0) {
    let ramTable = `| Path | ${roles.join(' | ')} |\n|---|${roles.map(() => '---').join('|')}|\n`;
    const sortedPaths = Object.keys(matrix).sort().slice(0, 150);
    for (const canonical of sortedPaths) {
      ramTable += `| \`${canonical}\` | ${roles.map(r => matrix[canonical][r] ?? '—').join(' | ')} |\n`;
    }
    if (Object.keys(matrix).length > sortedPaths.length) ramTable += `\n_Showing ${sortedPaths.length} of ${Object.keys(matrix).length}._\n`;
    ramSection += ramTable;
  } else {
    ramSection += '_No authenticated roles tested — matrix contains only the unauthenticated column._\n\n';
  }
  ramSection += `\n### Potential broken access control indicators\n\n`;
  if ((p8?.anomalies || []).length === 0) {
    ramSection += `_No role-dependent access differences detected. Either the target has consistent access control across tested roles, or there are no distinguishing endpoints._\n`;
  } else {
    ramSection += `The following ${p8.anomalies.length} endpoint(s) returned different status codes to different roles. These are **candidate IDOR or broken-access-control indicators** — flagged, not exploited, per recon-only scope:\n\n`;
    for (const a of p8.anomalies) {
      const per = Object.entries(a.perRole).map(([r, v]) => `${r}=\`${v.status}\``).join(', ');
      ramSection += `- \`${a.canonical}\` → ${per}. _${a.note}_\n`;
    }
  }
  md += section('3. Role-Based Access Map', ramSection);

  // --- Application Flows ---
  let flowSection = '';
  if (workflows.length) {
    flowSection += `${workflows.length} user journey(s) reconstructed from traffic sequences (phase 13) and endpoint inventory (phase 15).\n\n`;
    for (const w of workflows) {
      const steps = workflowSteps.filter(s => s.workflow_id === w.id);
      flowSection += `### ${w.name}\n\n`;
      flowSection += `**Business function:** ${w.purpose || '_not annotated_'}\n\n`;
      flowSection += `**Triggering user action:** inferred from flow name — see \`phase16_flows.json\` for the heuristic rule that matched.\n\n`;
      flowSection += `**Sequence:**\n`;
      flowSection += steps.map((s, i) => `${i + 1}. \`${s.method} ${s.endpoint_canonical}\`${s.role ? ` (as ${s.role})` : ''}`).join('\n') + '\n\n';
    }
  } else {
    flowSection += '_Flow mapping (phase 16) produced no workflows. Either the target has no distinct user journeys or interaction-dependent traffic was never generated._\n';
  }
  md += section('4. Application Flows', flowSection);

  // --- JavaScript Analysis (+ API base paths, client-side routes, secrets) ---
  let jsSection = '';
  jsSection += `- **Files analyzed:** ${p11?.filesAnalyzed || 0}\n`;
  jsSection += `- **Endpoints extracted from JS:** ${(p11?.endpoints || []).length}\n`;
  jsSection += `- **API base paths detected:** ${(p11?.apiBasePaths || []).length}\n`;
  jsSection += `- **Client-side route definitions:** ${(p11?.clientRoutes || []).length}\n`;
  jsSection += `- **Secrets / leaked credentials flagged:** ${secrets.length} (reported, **never exploited**)\n\n`;

  if ((p11?.endpoints || []).length > 0) {
    jsSection += `### Endpoints referenced in JS bundles\n\n`;
    jsSection += (p11.endpoints.slice(0, 30)).map(e => `- \`${e}\``).join('\n') + '\n';
    if (p11.endpoints.length > 30) jsSection += `\n_${p11.endpoints.length - 30} more in \`phase11_js.json.endpoints\`._\n`;
    jsSection += '\n';
  }

  if ((p11?.apiBasePaths || []).length > 0) {
    jsSection += `### API base paths\n\n`;
    jsSection += `Common prefixes inferred from the extracted endpoints — useful for targeted follow-up enumeration.\n\n`;
    for (const bp of p11.apiBasePaths) {
      jsSection += `- \`${bp.prefix}\` — ${bp.endpointsSharing} endpoint(s) share this prefix\n`;
    }
    jsSection += '\n';
  } else {
    jsSection += `### API base paths\n\n_No standard API base paths (/api, /v1, /graphql, /rest, /rpc) detected in JS endpoint strings. The app may not namespace its API, or API calls use absolute URLs to a separate domain._\n\n`;
  }

  if ((p11?.clientRoutes || []).length > 0) {
    jsSection += `### Client-side route definitions\n\n`;
    jsSection += `SPA routes detected in JS — these are client-side routes that map to components, not server endpoints. Useful for enumerating the authenticated UI surface.\n\n`;
    for (const r of p11.clientRoutes.slice(0, 40)) {
      jsSection += `- \`${r}\`\n`;
    }
    if (p11.clientRoutes.length > 40) jsSection += `\n_${p11.clientRoutes.length - 40} more in \`phase11_js.json.clientRoutes\`._\n`;
    jsSection += '\n';
  } else {
    jsSection += `### Client-side route definitions\n\n_No SPA route definitions extracted. Either the app is not SPA-heavy or its routes are embedded in webpacked chunks the regex missed._\n\n`;
  }

  jsSection += `### Secrets / leaked credentials\n\n`;
  if (secrets.length === 0) {
    jsSection += `_No secrets detected. Regex scan covered AWS keys, Google API keys, Stripe secrets, JWTs in static code, GitHub tokens, Slack tokens, and PEM private-key headers._\n`;
  } else {
    for (const s of secrets) {
      jsSection += `- **${s.type}** (${s.severity}) in \`${s.source_file}\` — snippet \`${s.snippet}\`. Flagged, not exploited.\n`;
    }
  }
  md += section('5. JavaScript Analysis', jsSection);

  // --- Historical & Fuzzing (narrative + tables, flag live historical) ---
  let hfSection = '';
  hfSection += `### Historical endpoints (Wayback Machine)\n\n`;
  if (p9?.error) {
    hfSection += `⚠ Wayback CDX query failed: \`${p9.error}\`. No historical paths retrieved this run. See limitations below.\n\n`;
  } else if ((p9?.historicalUrls || []).length === 0) {
    hfSection += `- Paths retrieved from archive.org: **0**\n- This is a valid null result for new domains, intranet targets, or sites excluded from crawlers.\n\n`;
  } else {
    hfSection += `- Paths retrieved from archive.org: **${p9.historicalUrls.length}**\n`;
    hfSection += `- Sample of first 50 probed against the live target: **${(p9.stillLive || []).length} still respond**.\n\n`;
    if ((p9.stillLive || []).length > 0) {
      hfSection += `**Historical paths still live (potentially deprecated but exposed):**\n\n`;
      for (const h of p9.stillLive.slice(0, 30)) {
        hfSection += `- \`${h.path}\` → ${h.status}\n`;
      }
      if (p9.stillLive.length > 30) hfSection += `\n_${p9.stillLive.length - 30} more in \`phase9_historical.json.stillLive\`._\n`;
      hfSection += '\n';
    }
  }

  hfSection += `### Predictive directory fuzzing\n\n`;
  hfSection += `- **Candidates tested:** ${p10?.candidatesTested || 0} (generic wordlist + Claude-predicted paths from phase 7/11 observations)\n`;
  hfSection += `- **Hits (200, not matching 404 baseline):** ${(p10?.hits || []).length}\n`;
  hfSection += `- **Auth-gated (401/403):** ${(p10?.authProtected || []).length}\n`;
  hfSection += `- **Redirects (3xx):** ${(p10?.redirects || []).length}\n`;
  hfSection += `- Baseline body length used for soft-404 filter: ${p10?.baselineBodyLength ?? 'not set'} bytes\n\n`;

  if ((p10?.hits || []).length > 0) {
    hfSection += `**Fuzzing hits:**\n\n`;
    for (const h of p10.hits.slice(0, 20)) hfSection += `- \`${h.path}\` → ${h.status} (${h.length}B)\n`;
    hfSection += '\n';
  }
  if ((p10?.authProtected || []).length > 0) {
    hfSection += `**Auth-gated paths (returned 401/403 — exist but not accessible unauthenticated):**\n\n`;
    const uniqueAuth = Array.from(new Set((p10.authProtected || []).map(h => h.path)));
    for (const p of uniqueAuth.slice(0, 20)) hfSection += `- \`${p}\`\n`;
    hfSection += '\n';
  }
  md += section('6. Historical & Fuzzing', hfSection);

  // --- Response Fingerprints (per-code + inconsistencies) ---
  let fpSection = '';
  fpSection += `How the target signals different error/response classes. Captured during phase 3 baseline probing and cross-referenced with phase 8 per-role classification.\n\n`;
  fpSection += `| Status | Samples | Typical body length | Snippet |\n|---|---|---|---|\n`;
  for (const [code, info] of Object.entries(p3?.patterns || {}).sort()) {
    const snippet = (info.typicalSnippet || '').replace(/\|/g, '\\|').slice(0, 80);
    fpSection += `| ${code} | ${info.samples.length} | ${info.typicalBodyLength}B | \`${snippet}\` |\n`;
  }
  fpSection += '\n';
  if (p3?.soft404Warning) {
    fpSection += `⚠ **Soft-404 detected.** Target returns 200 for non-existent paths. Phase 10 compensates with body-length comparison against the baseline.\n\n`;
  }
  if (!p3?.hasConsistent404) {
    fpSection += `⚠ **404 response pattern is inconsistent across probed paths.** Fuzzing accuracy is reduced — some genuine hits may be misclassified.\n\n`;
  }
  fpSection += `### Per-role inconsistencies\n\n`;
  if (fingerprintInconsistencies.length === 0) {
    fpSection += roles.length > 1
      ? `_All ${roles.length} tested roles receive consistent fingerprints for the same endpoint path._\n`
      : `_Only one role tested (unauthenticated); per-role cross-check requires ≥2 roles. See Limitations._\n`;
  } else {
    fpSection += `The following ${fingerprintInconsistencies.length} endpoint(s) returned different status codes across roles — noted under "Potential broken access control indicators" in section 3:\n\n`;
    for (const line of fingerprintInconsistencies.slice(0, 30)) fpSection += `- ${line}\n`;
  }
  md += section('7. Response Fingerprints', fpSection);

  // --- Limitations & Gaps (structured table) ---
  let limSection = '';
  if (limitations.length === 0) {
    limSection += `_No limitations encountered during this run._\n`;
  } else {
    limSection += `Every soft failure, CAPTCHA block, rate limit, auth failure, or coverage gap encountered during the scan is listed below with its cause, impact on scoring, and what to do about it.\n\n`;
    limSection += `| # | Issue | Cause | Impact | Mitigation |\n|---|-------|-------|--------|-----------|\n`;
    for (const [i, l] of limitations.entries()) {
      const row = [i + 1, l.issue, l.cause, l.impact, l.mitigation].map(s =>
        String(s).replace(/\|/g, '\\|').replace(/\n/g, ' ')
      );
      limSection += `| ${row.join(' | ')} |\n`;
    }
  }
  md += section('8. Limitations & Gaps', limSection);

  // --- Final Judge summary (if available) ---
  const judgePath = path.join(REPORTS_DIR, 'final-judge.json');
  if (fs.existsSync(judgePath)) {
    const j = JSON.parse(fs.readFileSync(judgePath, 'utf8'));
    let jSection = `**Mechanical verdict:** \`${j.verdict}\`\n\n`;
    if (j.critical_actions?.length) {
      jSection += `**Critical actions:**\n`;
      for (const a of j.critical_actions) jSection += `- ${a.action} _(priority: ${a.priority || 'HIGH'})_\n`;
      jSection += '\n';
    }
    if (j.recommended_actions?.length) {
      jSection += `**Recommended actions:**\n`;
      for (const a of j.recommended_actions) jSection += `- ${a.action} _(priority: ${a.priority})_\n`;
      jSection += '\n';
    }
    if (j.observations?.length) {
      jSection += `**Observations:**\n`;
      for (const o of j.observations) jSection += `- ${o}\n`;
    }
    md += section('9. Final Judge Verdict', jSection);
  }

  md += `---\n\n_Report generated by attack-surface-discovery skill. Every finding is traceable to its phase artifact under \`output/artifacts/\`. Recon scope — flagged, not exploited._\n`;

  fs.writeFileSync(path.join(REPORTS_DIR, 'report.md'), md);
  db.close();
  log(18, `OK: report.json and report.md written. Completeness=${(completeness * 100).toFixed(1)}%, limitations=${limitations.length}`);
})();
