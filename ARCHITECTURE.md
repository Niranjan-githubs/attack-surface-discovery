# Architecture Write-Up

**Submission:** Autonomous Attack Surface Discovery & Analysis
**Orchestrator:** Claude Code (SKILL.md-driven)
**Target tested:** OWASP Juice Shop (self-hosted, `http://localhost:3000`)

## 1. Design principle: thin orchestrator, deterministic scripts, reasoning at the seams

The brief is explicit that the orchestrator is *not* a passive script runner — it must sequence, quality-gate, and adapt. I took that literally: the orchestrator is `SKILL.md` itself, read by Claude Code, which calls one script per phase. Each script is small, single-purpose, writes an artifact JSON, and exits. Claude reads the artifact, validates against an expected shape, and decides whether to proceed, rework, or flag a gap. No monolithic Node process drives the pipeline end-to-end — that would put the reasoning in the wrong place.

Phases split cleanly along the deterministic vs. reasoning axis the brief calls out:

| Deterministic (script-only, no LLM tokens) | Reasoning (Claude Code judgment) |
|---|---|
| 1 accessibility, 2 metadata, 3 fingerprint, 4 app-type | 5 launch decision |
| 9 Wayback fetch, 11 JS regex extraction | 7 crawl strategy adaptation (per app type) |
| 14 param classification (regex/heuristic) | 10 fuzzing predictions (LLM picks paths from observed patterns) |
| 15 dedup/merge, 17 SQLite write | 16 flow mapping (LLM names workflows) |
|  | 8 response classification across roles (mostly scripted but LLM flags anomalies) |
|  | 18 report synthesis (LLM writes prose sections, script writes tables) |

LLM cost stays bounded because no phase feeds raw crawl data into a prompt — Claude sees summarized artifacts only.

## 2. Tool choices and why

- **Playwright over Puppeteer/Selenium.** `BrowserContext` gives one-line isolated sessions per role (phase 6/7 requirement), and `context.route()` captures every request cross-origin — which lets me skip running mitmproxy as a separate process. Phase 13 (traffic analysis) is implemented as a route handler attached during phase 7, not a separate interceptor. One fewer moving part, same artifact.
- **Node-based rate-limited fuzzer instead of ffuf.** Avoids a shell-out and lets me reuse the same HTTP client, cookies, and 404 baseline captured in phase 3. 4 concurrent requests with 100ms jitter — conservative enough not to trip Juice Shop's rate limits. `ffuf` would be faster on a huge wordlist but harder to feed per-role sessions.
- **cheerio for HTML parsing** (phase 2). The original orchestrator did regex against HTML, which breaks on anything non-trivial. cheerio is jQuery-like and cheap.
- **better-sqlite3 as storage.** Synchronous API means the phase-17 writer is ~30 lines; it's the *only* component that knows the schema (satisfies the "single translation point" requirement in §5.3). All other phases write JSON artifacts; the writer translates.
- **Wayback CDX API** for phase 9. Returns JSON, no auth, rate-friendly. `waybackurls`/`gau` are fine but adding a Go binary to the dependency graph isn't worth it.
- **Native `fetch` with AbortController** everywhere else. The original code used `fetch(url, {timeout})` which silently doesn't work — I switched to AbortController which is the correct pattern on Node 22.

## 3. Artifact-first, resumable

Every script writes to `output/artifacts/phase{N}_*.json` before returning. The orchestrator never holds crawl data in memory across phases — it passes file paths. This means:
- A crashed phase 10 doesn't lose phase 7's crawl (brief §6 artifact-first principle).
- The final report (phase 18) is assembled purely from artifacts. Re-running phase 18 against different artifacts produces a different report without touching the pipeline.
- Every finding in the report carries a `source` field pointing back to the phase that discovered it (brief §4 report requirement: "every finding traceable to its discovery source").

## 4. Generalizability — no target-specific logic

The brief warns that hardcoded target-specific patterns will fail the surprise evaluation. Defenses I took:
- No hardcoded endpoint lists. The only wordlist is SecLists-style generic paths (`api`, `admin`, `health`, `metrics`, etc.) plus LLM-predicted paths derived from what the crawler actually saw.
- App-type detection (phase 4) drives crawl strategy — SPAs get browser automation with event-firing; traditional apps get cheaper static link-following. No "if target == juice-shop" branches.
- Auth mechanism is sniffed from the login response (phase 6) — cookie vs. JWT vs. bearer is detected, not configured.
- Configured via `config.json` + `credentials.json`; no code change needed to point at a new target.

## 5. Quality gates — three layers

The brief explicitly warns that the orchestrator is not a passive script runner; it must validate outputs and trigger rework. I stacked three layers:

1. **Deterministic per-phase gate** (`scripts/phase-gate.js`). Runs after every phase, checks artifact shape + thresholds (e.g., "phase 15 inventory non-empty", "phase 8 matrix covers ≥50% of inventory"), emits `PASS | WARN | FAIL` with specific blockers/warnings. Can't be gamed because it's schema-level.
2. **Quality Reviewer subagent** (Claude-spawned, per phase transition, `full` mode only). Has session context, looks for upstream/downstream inconsistencies and soft failures the mechanical gate can't see (silent throttling, monotone status codes, missed techniques). Must produce 2–3 specific suggestions before advancing.
3. **Final Judge** (zero-context reviewer, post-phase-18). Spawned via Task tool with only the target URL and artifact paths in its prompt — no conversation history. Applies four lenses: coverage integrity, role-access consistency, flow plausibility, limitations honesty. Returns `PASS | CONDITIONAL_PASS | FAIL` with concrete remediation actions. The deterministic counterpart (`scripts/final-judge.js`) runs in CI.

This mirrors the AutoPentest pattern (Quality Reviewer with context + Final Judge without) but stripped of the pentest-specific checks — our Judge is recon-scope only.

## 6. Multi-domain scope + scope.avoid

`config.json` → `scope.domains` lets the skill treat SSO targets correctly. If the primary is `app.example.com` and login redirects to `auth.example.com`, both go in `domains` and every downstream phase (crawl, traffic, Wayback, API docs, dedup, storage) keys on `(domain, canonical)` rather than just path. The most common surprise-target failure mode is silently scanning only the app domain and missing auth/API hosts — the skill surfaces the redirect and edits the config before proceeding.

`scope.avoid` is a list of `{type: 'path' | 'regex', pattern, reason}` rules. Applied by the crawler and fuzzer (not by phases 9/12 since those probe remote services). Used to exclude destructive endpoints (`/logout`, `/admin/shutdown`) that would interfere with later phases.

## 7. Error model — three tiers, not generic "retry once"

Every failure maps to one of:
- **Tier 1 transient** (timeout, 502/503/504, Playwright `TimeoutError`): retry up to 3× with 2-4-8s backoff.
- **Tier 2 rate-limit / defensive** (429, WAF block page, `rate.?limit|captcha` in body): pause 30–60s, drop concurrency to 2, resume once. If still rate-limited, accept partial coverage and log to limitations.
- **Tier 3 permanent** (401/403 with valid creds, NXDOMAIN, scope violation, missing binary): do not retry. For auth failures, walk the 6-level Auth Failure Escalation (alternative grants → PKCE → headless browser with explicit selectors → token extraction from JS → ask user → unauthenticated fallback). Never silently degrade to unauthenticated — always log an Informational finding describing the coverage gap.

## 8. Resume-prompt

Every gate refreshes `output/resume-prompt.md` — a self-contained markdown file listing the target, completed phases, gate verdicts, artifact inventory, and next steps. Paste it into a fresh Claude Code session and the run continues from the next unstarted phase. The brief §6 artifact-first principle explicitly calls out resume capability; this is the entry point that makes it usable.

## 9. Trade-offs and what I'd improve with more time

- **GraphQL introspection (phase 12).** Currently I check common paths (`/graphql`, `/api`, `/v1/graphql`) and try an introspection query. Deeper parsing of the returned schema to enumerate mutations/queries as first-class endpoints would improve discovery on GraphQL-heavy targets. A GraphQL-only app would underperform today.
- **Parameter mutation analysis (phase 14) is heuristic.** I classify by name pattern (`id`, `token`, `timestamp`) and value volatility across requests. A learned classifier trained on many real apps would do better, but regex gets ≥80% and satisfies the acceptance bar.
- **No crawl-depth learning.** Depth cap is static (5). A smarter orchestrator would notice saturation (new endpoints per minute approaching zero) and terminate early. Added to the roadmap but skipped for time.
- **Report generation** uses a JS template for JSON/MD and relies on Claude's summarization for prose. HTML report is minimal. If I had another day I'd add an interactive endpoint-graph visualization (Cytoscape.js) so the flow map is navigable.
- **Session refresh validation.** The generated refresh script is invoked once at phase 6 end to confirm it works, but I don't currently run an end-to-end "let session expire → refresh → continue" drill. On a long-running scan against a target with 15-minute tokens this would matter.
- **Concurrency.** Phases 7–13 run sequentially today. The brief allows parallel execution of independent discovery sources. Parallelizing phases 9, 11, 12, and the Wayback fetch with phase 7's crawl would cut wall-clock time roughly in half.

## 6. Result on Juice Shop

See `output/reports/report.md` for the full output. Summary: 18 phases executed, artifacts in `output/artifacts/`, endpoints written to `output/storage/reconnaissance.db`, completeness score and limitations section honestly flagged in the report.
