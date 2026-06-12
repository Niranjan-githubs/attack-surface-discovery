



# Attack Surface Discovery

Autonomous reconnaissance skill for Claude Code. Maps a web application's attack surface through 18 phases — accessibility → crawling → fuzzing → flow mapping → report.

## Submission contents 

| File | Purpose |
|---|---|
| `SKILL.md` | Claude Code skill definition — the orchestrator |
| `ARCHITECTURE.md` | 1–2 page architecture write-up (design decisions, trade-offs, future work) |
| `scripts/` | Per-phase scripts invoked by the orchestrator |
| `config.json`, `credentials.json` | Target + auth configuration (edit per target) |
| `package.json` | Node dependencies |
| `output/` | Phase artifacts + final reports from the demo run |

## How it's meant to be run

**With Claude Code (the real submission):** drop the `attack-surface-discovery` folder into your skills directory and invoke it with a target URL. Claude reads `SKILL.md`, sequences phases, validates artifacts between each, makes judgment calls for phase 5 (strategy), 10 (fuzz predictions), and 16 (flow naming), and writes the final report.

**Automated demo run (this README's scripts):** `npm run scan` invokes `scripts/runner.js` which runs all 18 phases in order with deterministic fallbacks where Claude's reasoning would otherwise plug in. Produces the same artifacts and reports, just with less nuanced strategy/flow naming.

## Setup

```bash
cd attack-surface-discovery
npm install
npm run install-browsers    # playwright install chromium
```

Edit `config.json` to point at your target. Edit `credentials.json` if the target has auth (or delete the `roles` array for unauthenticated-only scanning).

## Run

```bash
npm run scan
```

Artifacts land in `output/artifacts/phase{N}_*.json`, SQLite DB in `output/storage/reconnaissance.db`, report in `output/reports/report.{json,md}`.

## Run one phase at a time

```bash
npm run phase1     # accessibility
npm run phase7     # active crawl (requires phase 1-6 to have run)
npm run query      # dump endpoint inventory from the DB
```


## Quality gates

Every phase (except 1 and 18) has a deterministic gate that reads its artifact and emits `output/gates/gate{N}.json` with `PASS | WARN | FAIL`, blockers, warnings, and brainstorming prompts. The runner calls each gate automatically; when Claude Code drives the skill, `SKILL.md` instructs it to also spawn a **Quality Reviewer** subagent per phase and a **Final Judge** zero-context reviewer after phase 18. See `SKILL.md` for the exact prompts.

`final-judge.js` is the heuristic version — it checks:
1. Coverage integrity (did every source contribute?)
2. Role-access consistency (matrix vs. inventory)
3. Flow plausibility (supported by traffic?)
4. Limitations honesty (are gate FAILs surfaced in the report?)

## Multi-domain scope

`config.json` → `scope.domains` controls which hosts are in-scope. If phase 2 or phase 6 discovers an off-domain login redirect (SSO / OAuth / OIDC / SAML), add the auth provider as a separate domain before proceeding — every downstream phase honors the list.

`config.json` → `scope.avoid` blocks specific paths (regex or literal) from being crawled or fuzzed. Useful for destructive endpoints like `/logout` or admin kill-switches.

## Modes

- `"mode": "full"` — default. All phases, all gates, Quality Reviewer per phase, Final Judge post-report.
- `"mode": "ctf"` — small/CTF targets. Quality Reviewer skipped; gates advisory.

## Resuming an interrupted run

Every gate refreshes `output/resume-prompt.md` with: the target, completed phases, gate verdicts, next phase to run, and file-map. Paste that file into a fresh Claude Code session to continue where you left off. Never delete `output/` between partial runs.

## Design principles

- **Artifact-first.** Every phase writes to a named file. The orchestrator never holds crawl data only in memory.
- **Single storage translation point.** Only `scripts/phase17-storage.js` knows the DB schema.
- **Deterministic vs. reasoning separation.** Scripts do the mechanical work; Claude does strategy, prediction, flow naming.
- **Generalizable.** No target-specific heuristics. Auth mechanism, app type, naming conventions are all detected at runtime.

## Troubleshooting

- **`Could not find browser`**: run `npm run install-browsers`.
- **`target unreachable`**: check `config.json` URL, verify target is actually running.
- **Phase 6 "login form interaction failed"**: target's login form uses non-standard field names. Add explicit `selectors` in `credentials.json` per role.
- **Phase 7 captures 0 endpoints**: likely hit a bot-detection page. Try `"strategy": "Traditional"` manually or lower concurrency.
- **`better-sqlite3` install fails on Windows**: needs a C++ toolchain. Run `npm install --build-from-source` or install VS build tools.

## Scope

Reconnaissance only. This skill flags exposed secrets, IDOR-shaped access anomalies, and broken-access-control patterns — it does not exploit them.
