---
name: attack-surface-discovery
description: Autonomously map a web application's attack surface. Use when the user provides a target URL (with optional credentials) and asks to discover endpoints, classify parameters, map application flows, test multi-role access, or produce a reconnaissance report. Pipeline is 18 phases from accessibility check through report generation. Scope is recon only — never exploit findings.
compatibility: Claude Code. Requires Node 22+, Playwright, and the scripts in ./scripts/. Optional but honored if present on PATH — mitmproxy, ffuf.
---

# Attack Surface Discovery — Orchestrator Skill

You are driving an 18-phase reconnaissance pipeline against a web application. You are not a passive script runner: you sequence phases, quality-gate every artifact, trigger rework on malformed output, and assemble the final report. Scripts do the deterministic work; you do the judgment.

## How to invoke

The user provides a `config.json` (target URL, output dir, limits, scope, mode) and optionally a `credentials.json` (per-role login creds). If either is missing, ask once. If the user says "just scan \<url\>", create a minimal config inline and proceed unauthenticated.

Before running any phase, `cd` into the skill directory and confirm `scripts/` exists. All artifacts land in `output/artifacts/phase{N}_*.json`. You read those files — you do not hold crawl data in context.

### Modes

- **`full`** (default) — all 18 phases, full quality gates, Quality Reviewer per phase, Final Judge post-report.
- **`ctf`** — small/CTF targets (<5 endpoints, no auth). Quality Reviewer skipped. Phase gates advisory. Final Judge still runs but with relaxed thresholds.

Set mode in `config.json`. When in doubt use `full`.

### Multi-domain scope (mandatory check during phase 2)

If phase 2 or phase 6 reveals the target redirects to a different host for login (SSO / OAuth / OIDC / SAML / Keycloak / Auth0 / Okta), treat every such host as **in-scope and independent**. Before phase 7:

1. Add each domain to `scope.domains` in the config via a single edit.
2. Phase 7 crawls every in-scope domain, not just the primary.
3. Phase 9 (Wayback) queries each domain.
4. Phase 12 (API docs) probes each domain.
5. Phase 15 dedup keys are `(domain, canonical)` not just `canonical`.

A test is only "not applicable" when the condition fails on **every** in-scope domain. Marking N/A on the primary because it's a static SPA, while ignoring a server-side auth provider on a different domain, is the single most common failure mode — don't do it.

## Pipeline invariants (read every time)

1. **Artifact-first.** Every phase writes to a named file under `output/artifacts/` before you evaluate it. If a script returned but the artifact file is missing or zero bytes, that phase failed — rerun or flag.
2. **Single storage translation point.** Only `scripts/phase17-storage.js` knows the SQLite schema. If you need to query results, query the DB, don't re-parse artifacts.
3. **Deterministic vs. reasoning.** Phases marked *script* below take no judgment from you — run them, validate the schema, move on. Phases marked *reason* are where you spend tokens: crawl strategy (7), fuzz prediction (10), flow naming (16), report prose (18).
4. **No target-specific logic.** If you catch yourself writing a branch that says "if the target is juice-shop", delete it. The evaluation target is unknown.
5. **Flag, don't hide.** Session expiry, CAPTCHAs, rate limits, unreachable endpoints — all go in the `limitations` artifact, not silently skipped.

## Phase execution

Run phases strictly in order. For each: run the script, read the artifact, validate, decide. If validation fails, rerun once with tightened parameters; if it fails twice, write a `phase{N}_error.json` and continue (so the final report can honestly note the gap).

### Phase 1 — Accessibility *(script)*
```
node scripts/phase1-accessibility.js
```
Artifact: `phase1_accessibility.json`. Valid if `accessible: true` and `statusCode < 500`. If unreachable, STOP — write a single-section report explaining and exit. Don't continue.

### Phase 2 — Metadata *(script)*
```
node scripts/phase2-metadata.js
```
Artifact: `phase2_metadata.json`. Valid if `initialEndpoints.length >= 3` and `techStack` has at least one framework or server detected. If the page was a client-rendered shell (empty `<body>`), that's fine — phase 4 will classify as SPA and phase 7 will fill in endpoints via browser.

### Phase 3 — Baseline fingerprinting *(script)*
```
node scripts/phase3-fingerprint.js
```
Artifact: `phase3_fingerprint.json`. Valid if at least a 404 pattern is captured. Flag if the app returns 200 for non-existent paths — every later phase needs this to avoid false positives.

### Phase 4 — App type detection *(script)*
```
node scripts/phase4-apptype.js
```
Artifact: `phase4_apptype.json`. Classification is SPA / Traditional / Hybrid with a confidence score. Low confidence (<0.6) is acceptable but note it — phase 7 will treat it as Hybrid (crawl both ways).

### Phase 5 — Launch *(reason)*
You read phases 1–4. Decide crawl strategy for phase 7:
- SPA: browser with event-firing, depth 5, wait for XHR settle.
- Traditional: link-following, depth 7, cheaper.
- Hybrid: browser but skip event-firing on pages without JS routes.
Write `phase5_launch.json` recording the decision with a one-line rationale. This is *your* artifact — no script.

### Phase 6 — Auth profiling *(script, but you verify)*
```
node scripts/phase6-auth.js
```
One session per role in `credentials.json`. Artifact: `phase6_auth.json` with cookies/tokens per role and a generated refresh script at `output/auth/refresh-{role}.js`. After the script completes, *you verify* by running the refresh script for one role and checking the session still works. If no credentials file exists, record `roles: [unauthenticated]` and skip the rest. If login fails for a role, write the failure to the artifact and continue with the roles that worked — don't block the whole scan.

### Phase 7 — Active crawling *(script, driven by your strategy)*
```
node scripts/phase7-crawl.js --strategy=<SPA|Traditional|Hybrid>
```
Uses the decision from phase 5. Crawls per-role. Artifact: `phase7_crawl.json`. Also writes `phase13_traffic.json` as a side effect (Playwright route interception captures every request). Validate: ≥ 10 endpoints for unauthenticated, ≥ 15 per authenticated role on any reasonably-sized target. If counts are far lower, diagnose — wrong strategy? rate-limited? — and rerun once.

### Phase 8 — Response classification *(script)*
```
node scripts/phase8-classify.js
```
Tests every endpoint from phase 7 against every role + unauthenticated. Artifact: `phase8_classify.json` with per-role status codes and the role-access matrix. You do not re-reason about each row; but do scan for anomalies: endpoints where admin returns 401 while user returns 200 usually indicate an auth bug worth flagging in the report.

### Phase 9 — Historical retrieval *(script)*
```
node scripts/phase9-wayback.js
```
Wayback CDX API. Artifact: `phase9_historical.json`. Probes historical paths against live target; flags ones still accessible. No validation gate — zero historical endpoints is a valid result for a new app.

### Phase 10 — Predictive fuzzing *(reason + script)*
Read `phase2_metadata.json`, `phase7_crawl.json`, `phase11_js.json` (if phase 11 already ran — otherwise skip it for now and come back). Identify naming conventions you see (camelCase? kebab? pluralization?), framework (Express? Rails? Laravel?). Output a predictions file `output/artifacts/phase10_predictions.json` with 30–60 paths you think might exist, as an array of `{path, rationale}`. Then:
```
node scripts/phase10-fuzz.js
```
The script reads your predictions + a generic wordlist and tests both. Output: `phase10_fuzz.json`. Quality gate: if zero new endpoints found, either the target is exhaustively mapped already (good) or your predictions were bad (look again). Do not rerun more than once — fuzzing is the noisiest phase.

### Phase 11 — JavaScript analysis *(script)*
```
node scripts/phase11-js.js
```
Downloads JS files discovered in phase 7 and regex-extracts endpoint patterns + secrets (API keys, JWTs, AWS keys). Artifact: `phase11_js.json`. Secrets go in the `limitations` section of the final report flagged, **never exploited**.

### Phase 12 — API documentation discovery *(script)*
```
node scripts/phase12-apidocs.js
```
Probes `/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql`, `/v1/graphql`, `/swagger-ui`, etc. If a GraphQL endpoint responds, attempts introspection. Artifact: `phase12_apidocs.json`. If a spec is found, its endpoints are high-confidence — mark source as `api-spec` in phase 15.

### Phase 13 — Passive traffic *(already captured in phase 7)*
No script invocation. The phase 7 crawler attached a Playwright route handler that wrote every observed request to `phase13_traffic.json`. Read and validate it exists; flag if empty (means phase 7 didn't actually route-intercept).

### Phase 14 — Parameter mutation *(script)*
```
node scripts/phase14-params.js
```
Classifies parameters as static/dynamic/unknown across all observed requests. Artifact: `phase14_params.json`. CSRF tokens, JWTs, timestamps are flagged. Acceptance: ≥80% of parameters classified (not "unknown").

### Phase 15 — Deduplication & merge *(script)*
```
node scripts/phase15-dedup.js
```
Merges endpoint lists from phases 7, 9, 10, 11, 12, 13. Canonicalizes paths (trailing slashes, parameter normalization `GET /users/:id`). Every endpoint carries a `sources: []` array — full provenance. Artifact: `phase15_endpoints.json`. This is the master inventory.

### Phase 16 — Flow mapping *(reason)*
Read `phase13_traffic.json` (request sequences) and `phase15_endpoints.json`. Identify 3–8 user journeys — name them in business terms (e.g., "Registration", "Product browse → cart → checkout", "Admin user management"). Each flow is `{name, purpose, steps: [{endpoint, method, role}], dependencies: []}`. This is pure LLM work — you write `phase16_flows.json` directly. Refuse to invent flows that aren't supported by observed request sequences.

### Phase 17 — Storage write *(script)*
```
node scripts/phase17-storage.js
```
Reads all phase artifacts and writes to `output/storage/reconnaissance.db`. Schema: `endpoints`, `parameters`, `role_access`, `workflows`, `artifacts`. Artifact: `phase17_storage.json` with row counts. Validate counts > 0 for `endpoints` and `role_access`.

### Phase 18 — Report generation *(reason + script)*
Run the templater first:
```
node scripts/phase18-report.js
```
It produces `output/reports/report.json` (structured) and skeleton `report.md` with tables filled in from the DB. You then write the prose sections directly into `report.md`: **Target Summary**, **Application Flows** (narrative of each flow from phase 16), **Limitations & Gaps** (honest account of what failed or was skipped), and any observations that came out of phase 8's anomaly scan. Required sections per brief §4:
- Target Summary
- Endpoint Inventory
- Role-Based Access Map
- Application Flows
- JavaScript Analysis
- Historical & Fuzzing
- Response Fingerprints
- Limitations & Gaps

The completeness score is computed by the script from real counts — don't override it.

## Phase gates — mandatory between phases

After every phase except 1 and 18, run:
```
node scripts/phase-gate.js <N>
```
It reads `phase{N}_*.json` and emits `output/gates/gate{N}.json` with `verdict: PASS | WARN | FAIL`, a list of blockers, a list of warnings, and brainstorming prompts for a human reviewer.

- **PASS** → proceed to phase N+1.
- **WARN** → proceed, but capture the warnings verbatim in the `limitations` field you'll assemble in phase 18.
- **FAIL** → rerun phase N once with tightened parameters (lower concurrency, bigger timeout, different strategy). If it fails a second time, write `phase{N}_error.json` with the blockers and continue so the rest of the pipeline still produces partial output.

The gate script is deterministic — use it, don't try to reimplement its checks in your head.

### Quality Reviewer (run after every phase gate in `full` mode)

After each gate returns PASS or WARN, spawn a Quality Reviewer subagent via the Task tool. It has session context but a focused job: catch what the gate misses.

Prompt template (fill the braces):

> "You are the Quality Reviewer for phase {N} of the attack-surface-discovery skill, target={target_url}.
>
> Read:
> 1. `output/artifacts/phase{N}_*.json` — what this phase produced.
> 2. `output/gates/gate{N}.json` — the mechanical gate's verdict.
> 3. `output/artifacts/phase{M}_*.json` for every M < N where the artifact exists — upstream state.
>
> Answer four questions, each in 1–3 sentences:
> 1. Did this phase miss anything an experienced pentester would have caught? (Be specific — endpoint, parameter, or technique.)
> 2. Are there inconsistencies between this phase's output and upstream phases? (e.g., phase 2 saw a framework, but phase 4 classified the app inconsistently.)
> 3. Is there evidence this phase was silently throttled, blocked, or hit a soft failure? (Short artifacts, empty arrays, monotone status codes.)
> 4. What are 2–3 specific actions worth taking before proceeding?
>
> Output a JSON object: `{passed: bool, gaps: [...], suggestions: [...]}`. Do not send HTTP requests. Do not modify artifacts. Do not re-run phases — only review."

Act on at least one `suggestions[]` entry before advancing — even a small rerun (e.g., bumping crawl depth, adding a login selector) is fine. Skip the Quality Reviewer entirely when `config.json` has `mode: ctf`.

## When things go wrong — three-tier error classification

Every transient failure falls into one of three tiers. Match first, then apply the policy — don't invent a fourth tier.

### Tier 1 — Transient (retry with short backoff)

Connection timeouts, 502/503/504, sporadic DNS hiccups, socket hang-ups, Playwright `TimeoutError` on networkidle.

- Retry up to **3 times** with 2s → 4s → 8s backoff.
- On third failure: write `phase{N}_error.json`, continue with partial output.

### Tier 2 — Rate-limit / defensive (retry with long backoff)

HTTP 429, Cloudflare / AWS WAF / Akamai block pages, body content matching `/rate.?limit|too many|captcha|access denied/i`, repeated 403 only on high-concurrency requests.

- Pause 30–60s.
- Drop `concurrency` in `config.json` to 2 and double `jitterMs`.
- Resume the same phase. Do **not** loop endlessly — if the second attempt still rate-limits, mark "rate-limited by target" in the limitations artifact and accept partial coverage.

### Tier 3 — Permanent (do not retry)

401/403 with valid credentials, DNS NXDOMAIN, missing binary (`playwright not installed`), scope violation, "invalid certificate" on non-target.

- Do **not** retry — retrying guarantees the same result.
- For auth failures: execute the Auth Failure Escalation below before giving up.
- For tool/config failures: fix the root cause, then rerun the phase from scratch (gates will reset).
- For DNS/scope failures: stop, surface to the user.

## Auth Failure Escalation (when phase 6 reports any role with `success: false`)

Walk the ladder in order. Do not skip levels and do not silently degrade to unauthenticated-only.

1. **Alternative grants.** If the target exposes `/.well-known/openid-configuration`, read `grant_types_supported`. Try `password` grant, then `client_credentials`. Record what you tried in `phase6_auth.json`.
2. **PKCE / OIDC code flow.** If the login redirects off-domain, add the auth provider to `scope.domains` and re-run phase 6 with the PKCE flow. Most Auth0 / Keycloak / Okta setups work this way.
3. **Headless browser with explicit selectors.** If the form is JS-rendered and the heuristic selectors missed it, ask the user for CSS selectors and add them to `credentials.json` under the role's `selectors` field. Rerun phase 6.
4. **Hardcoded tokens in JS bundles.** Check `phase11_js.json` for any `Bearer` tokens, API keys, or session IDs. If found, they count as a **finding** (secret exposure) but do not reuse them for scanning — that violates recon-only scope.
5. **Ask the user.** One clear message: "Automated login for role `{role}` failed at all automatable levels. Provide a session cookie or Authorization header value captured from a logged-in browser (F12 → Application → Cookies, or Network → copy header)." Then paste what they give you into `output/auth/state-{role}.json` in Playwright storageState format.
6. **Unauthenticated fallback.** If (5) is refused or unavailable, proceed with unauthenticated-only testing for that role and log an **Informational** finding describing the auth gap and its coverage impact. Mark auth-required phases as `skipped` (not `not_applicable`) with the reason "Authentication unavailable — escalation exhausted".

### What stays testable even if every role fails to auth

Do NOT give up on the scan. These phases run fine unauthenticated:

- Phase 1 (accessibility), 2 (metadata), 3 (fingerprint), 4 (apptype), 5 (launch)
- Phase 7 (crawl) — reduced coverage, but public pages + public XHR endpoints still map
- Phase 9 (Wayback), 11 (JS analysis), 12 (API docs) — completely independent of auth
- Phase 10 (fuzz) — unauthenticated fuzzing still surfaces public endpoints
- Phase 13 (traffic) — still captured during phase 7
- Phase 14 (params), 15 (dedup), 16 (flows), 17 (storage), 18 (report) — operate on whatever data the upstream produced

Phase 8 (response classification) still runs — it just classifies unauthenticated responses only. Phase 6 artifact records `roles: ['unauthenticated']`.

## Resuming an interrupted run

Every gate writes `output/resume-prompt.md` via `scripts/resume-prompt.js`. If this run is interrupted (crash, limit hit, user cancellation), a new session can paste `output/resume-prompt.md` verbatim and continue from the next unstarted phase — it contains the target, which phases completed, which artifacts exist, and what to do next.

To generate it ad-hoc: `node scripts/resume-prompt.js`.

Never delete `output/` between partial runs; the artifacts are the resume mechanism. If you want a clean slate, delete the whole directory.

## Anti-patterns (all of these have cost us points on past evaluations)

- **Marking a test `not_applicable` without checking every in-scope domain.** "Target is a static SPA" is never a valid N/A if the scope also contains an auth provider or API gateway.
- **Skipping a phase "to save time".** Endpoint Discovery Completeness is 30% of the score; each skipped source visibly shrinks the inventory.
- **Branching on target specifics.** `if target.includes('juice-shop')` or hardcoded endpoint lists will fail on the surprise evaluation target. If you catch yourself, delete it.
- **Over-trusting active crawl.** Phase 7 misses ~30% of endpoints on real apps. Phases 9–13 exist to cover that gap. Running just phase 7 is a C-grade scan at best.
- **Writing prose in phase 18 before reading the DB.** The numbers in `reconnaissance.db` are the ground truth. Do not let narrative drift from the data.
- **Calling a run complete without the Final Judge.** The Judge is the last independent check. Skipping it risks shipping a report that contradicts its own tables.
- **Silent failures.** Every failure goes in the `limitations` section of the report, not a comment in some artifact no reviewer will read.

## Honesty framework (recon edition)

The brief is recon-only — we are not claiming exploitability. Apply these rules to the report:

1. **Flag, never exploit.** Exposed admin endpoints, leaked secrets, IDOR-shaped access anomalies: describe them, include the evidence path in artifacts, never demonstrate exploitation.
2. **Distinguish observation from inference.** "Endpoint `/api/admin/users` returned 200 to role `user`" is an observation. "Role `user` has admin-level access" is an inference — fine to make, but label it that way.
3. **Never upgrade severity without evidence.** If you tag a secret as "critical", there must be a specific artifact and location cited.
4. **"No finding" is a finding.** If phase 10 returned zero new endpoints, say so — that's genuine coverage information. Don't hide empty results.
5. **Every claim in the Target Summary and Limitations sections maps back to an artifact path.** The Final Judge will cross-check this.

## Final Judge — mandatory before presenting the report

After phase 18 produces `report.md` and `report.json`, spawn exactly one zero-context reviewer via the Task tool. The Judge must not see this conversation's history — that's the whole point.

Prompt template (fill the braces, include nothing else):

> "You are the Final Judge for an attack-surface-discovery run on `{target_url}`. You have zero prior context — treat this as an external QA review.
>
> Inputs:
> - `output/reports/report.md`
> - `output/reports/report.json`
> - `output/artifacts/phase*.json`
> - `output/gates/gate*.json`
>
> Apply four lenses and produce a single verdict:
>
> **Lens 1 — Coverage integrity.** Did every discovery source (crawl, historical, fuzz, JS, API docs, traffic) actually contribute endpoints? If one contributed 0, is that honestly limitations-documented or silently hidden?
>
> **Lens 2 — Role-access consistency.** Does the role-access matrix agree with phase 8's raw classifications? Are anomalies from phase 8 actually surfaced in the report?
>
> **Lens 3 — Flow plausibility.** Does each workflow in section 4 actually have supporting request sequences in `phase13_traffic.json`? Reject flows named from generic pattern-matching that no real user journey supports.
>
> **Lens 4 — Limitations honesty.** Are all soft failures (rate limits, soft-404s, auth-blocked roles, missing specs) listed? Cross-check against `phase*_error.json` and gate WARN/FAIL outputs.
>
> Output this exact structure:
> ```json
> {
>   \"verdict\": \"PASS | CONDITIONAL_PASS | FAIL\",
>   \"critical_actions\": [...],   // only if FAIL
>   \"recommended_actions\": [...], // if CONDITIONAL_PASS or FAIL, with priority HIGH|MEDIUM|LOW
>   \"observations\": [...]
> }
> ```
> Be concrete: \"Run phase 10 with `/api/v2` prefix added\", not \"run more tests\"."

On the verdict:
- **PASS** → present the report to the user.
- **CONDITIONAL_PASS** → execute every HIGH-priority recommended action (typically a targeted rerun of one phase), then regenerate phase 18 and present.
- **FAIL** → execute every critical_action, then regenerate phase 18 and present.

You may also run `node scripts/final-judge.js` for a heuristic cross-check — it flags a subset of the issues above deterministically and is what the automated runner uses when there's no Claude-in-the-loop.

## What not to do

- Don't exploit findings. Flag them in the report with evidence paths and move on.
- Don't test hosts outside `scope.domains`. The Wayback phase queries archives for in-scope domains only.
- Don't write summary files outside `output/`. No pollution of the repo.
- Don't use `npm install` inside a phase script at runtime. Deps are installed once via `npm install` at setup.
- Don't edit artifact files after they're written. If a phase produced the wrong thing, rerun the phase — artifacts are provenance, not scratchpads.
