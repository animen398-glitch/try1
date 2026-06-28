# Memory — asa-claude

> Generated: 2026-06-28 14:10:00  
> Total memories: **58**  
> Breakdown: instruction: 8, decision: 11, goal: 4, preference: 1, context: 3, event: 25, artifact: 2, error: 4

---

## Instructions

*Standing rules, constraints, and guidelines to always follow.*

### Install/run/test/lint commands

Commands: install dev deps = pip install -r requirements-dev.txt ; run tests = pytest (offline, headless Qt offscreen) ; run GUI = python main.py ; lint = ruff ; demo workspace = ASA_DATA_ROOT=<dir> python main.py (after demo_seed.py). All tests must stay offline (stub network/subprocess); never require real internet or external binaries.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T14:49:13 | Tags: `commands`, `build`, `test`, `lint`*

### User permitted frozen/PyInstaller smoke for Client...

User permitted frozen/PyInstaller smoke for Client-Safe Pentest Workbench release-readiness if it does not interfere with Claude Code. Codex will run it locally in the current worktree only, with no remote git actions and no source changes intended.

*Confidence: 1 | Status: active | Created: 2026-06-27T17:34:49 | Tags: `client-safe-workbench`, `frozen-smoke`, `release-readiness`, `permission`*

### User explicitly told Codex to continue past the mi...

User explicitly told Codex to continue past the missing Client-Safe Pentest Workbench contract blocker, so Codex may implement the minimal roadmap-defined core contract locally for Stage 1 tests while preserving boundaries: no protected stores/path/config/project edits, no exploitation/bruteforce/stealth, no remote git.

*Confidence: 1 | Status: active | Created: 2026-06-27T17:11:00 | Tags: `client-safe-workbench`, `core-contract`, `permission`, `stage-1`*

### User assigned Codex current zone: internal polish,...

User assigned Codex current zone: internal polish, tests, release-readiness, and later GUI. Allowed now: tests/*, utils/*, core/features.py, core/launcher.py, core/project_io.py, demo_seed.py, release/self-check tooling, development-process documentation. Later only by separate stage: gui/*, gui/theme.py, gui/ui_components.py, gui/tab_*.py. Do not touch without separate confirmation: core/project.py, core/config.py, core/paths.py, core/collection_runner.py, core/findings_store.py, core/asset_store.py, CLAUDE.md, AGENTS.md, MEMORY.md, requirements*.txt, build.spec, README.md. Current focus: audit tests/release-readiness and propose 3-5 safe small tasks; no GUI design until separate command; any tests offline/headless.

*Confidence: 1 | Status: active | Created: 2026-06-27T15:04:48 | Tags: `codex-zone`, `release-readiness`, `tests`, `gui-later`*

### User confirmed Stage 2 GUI can proceed for Client-...

User confirmed Stage 2 GUI can proceed for Client-Safe Pentest Workbench Audit Runs after Stage 1 contract hardening commit 1c5a5a1. GUI must stay thin, use _run_async/_start_task for long-running actions, and avoid business logic.

*Confidence: 1 | Status: active | Created: 2026-06-27T17:14:45 | Tags: `client-safe-workbench`, `stage-2`, `gui`, `audit-runs`*

### Git policy and no-tech-debt rule

Git policy: local commits ARE the norm (Claude may commit verified pytest/ruff-clean units with meaningful messages; build artifacts dist/ build/ temp/ stay out per .gitignore). FORBIDDEN without explicit one-off user permission: git push/fetch/pull/clone, PRs, changing remote/origin, releases, any GitHub/remote action. Also forbidden: tech debt, hacks, stub-for-later, copy-paste logic, duplicate functionality, rewriting working code without need.

*Confidence: 1 | Status: active | Created: 2026-06-27T14:49:16 | Tags: `git-policy`, `rules`, `no-tech-debt`*

### User assigned Codex in current worktree to Stage 1...

User assigned Codex in current worktree to Stage 1 Client-Safe Pentest Workbench contract hardening: add edge-case tests for audit_workflow, scope_policy, action_policy, finding_validation, finding_quality, audit_schema and schemas; do not design core contract independently; GUI only after confirmation; no remote git or protected core store/path/config edits.

*Confidence: 1 | Status: active | Created: 2026-06-27T16:50:17 | Tags: `client-safe-workbench`, `contract-hardening`, `codex-zone`, `tests`*

### User instructed for this project: work only inside...

User instructed for this project: work only inside the current git worktree; never work in the main project-main folder; do not change another agent's responsibility zone; do not touch shared/config/lock/build/docs without separate approval; never git push/fetch/pull/clone/create PR; do not commit unverified code; if a contract from another agent is needed, stop and report required file/contract, purpose, minimal API/data shape, and tests for the contract.

*Confidence: 1 | Status: active | Created: 2026-06-27T15:04:10 | Tags: `worktree`, `git-policy`, `agent-boundaries`, `contracts`*

---

## Facts

*Verified information, project status, and established truths.*

*No memories of this type.*

---

## Decisions

*Architectural choices, approach selections, and their rationale.*

### Workbench v2 plan APPROVED by user (2026-06-28). 4...

Workbench v2 plan APPROVED by user (2026-06-28). 4 open decisions RESOLVED: (1) create_audit_run without template keeps v1 behavior = full 6 phases, payload identical, templates opt-in (backward-compat). (2) authenticated_review allows ONLY safe active checks (headers/cookies/TLS/sourcemaps/graphql-introspection/non-destructive probe/dependency-CVE); ZERO credential collection/brute/auto-login/auth-bypass/persistence; operator brings authorized session out-of-band as context, tool never acquires it; still gated by action_policy/scope_policy/ROE. (3) A/B compare is DERIVE-ON-READ from two stored run payloads, NO new SQLite table; only a lightweight 'compared' event with summary written to existing audit_events. (4) release compare_gate treats a FAILED candidate phase as inconclusive (not regression/resolved); never fails release solely due to a failed phase (mirrors Scan Diff). Implementation order F1 templates -> F2 ROE -> F3 revalidation -> F4 compare -> F5 reports, one feature at a time with tests + section-7 report. Code not yet started; awaiting user 'go' to begin F1.

*Confidence: 1 | Status: active | Created: 2026-06-28T00:29:56*

### Roadmap updated in commit 3af7604 with EPIC FUTURE...

Roadmap updated in commit 3af7604 with EPIC FUTURE — Client-Safe Pentest Workbench: product frame, 6 Audit Run phases, core contracts, quality gate, additive runs, GUI Audit Runs, safe active checks, forbidden client-safe actions, Claude/Codex split, and DoD.

*Confidence: 1 | Status: active | Created: 2026-06-27T16:45:43*

### User approved implementation of the Client-Safe Pe...

User approved implementation of the Client-Safe Pentest Workbench development plan. Codex will start with W1 Persistent Audit Runs core slice: add audit_store and tests, no GUI yet, no protected project/config/path/findings/asset store edits.

*Confidence: 1 | Status: active | Created: 2026-06-27T18:34:22 | Tags: `client-safe-workbench`, `w1`, `audit-store`, `approved`*

### Planning direction proposed for Advanced Site Anal...

Planning direction proposed for Advanced Site Analyzer: evolve from ASM/CSM + Client-Safe Audit Runs into an Authorized Pentest Workbench by adding mission/scenario orchestration, tool adapters, evidence-first validation, ROE-gated active checks, operator profiles, lab mode, reporting, and plugin SDK; avoid stealth, brute force, destructive exploitation, and unscoped automation by default.

*Confidence: 0.95 | Status: active | Created: 2026-06-28T00:15:32*

### Workbench v2 epic COMPLETE + committed locally (ma...

Workbench v2 epic COMPLETE + committed locally (master, commits 86e473f1 F1, 859d8249 F2, 3175fcfa F3, 98b0fcc5 F4, ab7ce310 F5, roadmap doc). All 5 features implemented with tests: F1 core/audit_templates.py (4 scenarios), F2 ROE templates in core/audit_scope.py, F3 core/audit_revalidation.py (overlay, no lifecycle writes), F4 core/audit_compare.py + schemas/asa_audit_compare.schema.json (derive-on-read, failed phase=inconclusive), F5 compare+scenario renderers in core/audit_report.py. Verified: ruff clean, full pytest 2064 passed (1 known Starlette warning), main.py --self-check 29 tabs. Single FindingsStore SoT preserved, schema growth additive/optional, all client-safe. DEFERRED to Codex (contract-only): GUI selectors/buttons in gui/tab_audit_runs.py, remote/web_app.py read parity, optional persisted 'compared' event. Roadmap section 'EPIC CLOSED - Workbench v2' added. CLAUDE.md/AGENTS.md/PROJECT_STATUS.txt status banners NOT yet synced.

*Confidence: 1 | Status: active | Created: 2026-06-28T01:04:26*

### Backend release-hardening contracts (T1-T5)

Backend release-hardening (branch backend/release-hardening, ~23 commits, full-diff self-reviewed, awaiting external review/merge; not pushed). SQLite/stores: (1) SQLiteStore: every connection WAL + synchronous=NORMAL + busy_timeout (no 'database is locked'); raw .db never copied so WAL sidecars safe. (2) Corrupt DB on init quarantined to <db>.corrupt-<ts>, recreated empty (never deletes data); transient lock != corruption. (3) FindingsStore.sync/AssetStore.sync = ONE transaction (atomic) via _upsert/_set_status/_list_* (conn) workers behind thin public wrappers. (4) OperationRegistry bounds operations.db (newest MAX_HISTORY, prune every PRUNE_EVERY inserts); DataRegistry user data NOT auto-pruned. (5) CVEStore.prune bounds cve_cache.db by age + row cap; cve_intel.correlate prunes once per run (own store only). Contracts/IO: (6) all 6 *_cli.py share core/cli_common.py (configure_stdout+CliError+run_main): expected failures -> stderr 'error: <msg>' + exit 2. (7) remote/web_app.py global FastAPI handler -> uniform {'error':...} JSON 500; _job_results FIFO-capped + _log_queue maxsize drop-oldest. (8) CollectionRunner._persist_error_report always leaves a readable report.json (status Error) on finalization failure. (9) external_tools.run_command caps stdout (MAX_OUTPUT head, truncated flag). (10) utils/atomic_io.py (temp+os.replace) for ALL durable-state JSON: metadata+history, report.json, company registry, evidence_manifest, settings/targets (transient per-phase artifacts left direct). (11) Project.start_scan unique scan dir (mkdir exist_ok=False + -2/-3 suffix); runner takes scan_id from scan_dir.name. (12) Secret previews are a non-leaking mask: secret_scanner._preview = prefix(6)+ellipsis+length (mirrors mask_value, never the body) + dynamic_analyzer previews aligned. IMPORTANT: the length suffix is required - findings_adapter derives the secret discriminator from key:preview, so a too-short preview (prefix only) would merge two distinct same-prefix keys (e.g. two sk_live_ keys) into one finding; the length restores that entropy (caught in self-review). Audits, NO code change (some pinned by guard tests): event ordering deterministic; report consumers tolerant of thin/legacy/Error reports (test_report_backcompat); migration-with-data tested (test_findings_store_migration); secret redaction OK (operations.db/logs carry no secrets; raw only in local artifacts + LAN console, by-design); timestamps consistently local-naive, ct_history isolated naive-UTC, no mixed comparison, UTC migration intentionally not done. Remaining optional/deferred: cross-process advisory locking; roadmap-out-of-scope (live threat feeds, live cloud API, new scanners).

*Confidence: 0.9 | Status: active | Created: 2026-06-27T16:28:31 | Tags: `backend-hardening`, `sqlite-wal`, `atomic-sync`, `atomic-writes`, `cli-contract`, `web-error-envelope`, `retention`, `scan-dir-unique`, `secret-redaction`, `diff-reviewed`, `release-readiness`*

### KEV/EPSS Threat Intelligence Feed epic COMPLETE + ...

KEV/EPSS Threat Intelligence Feed epic COMPLETE + committed locally (master). Commits: 3017251f F1 (core/threat_feed.py KEV+EPSS parsers + CVEStore.cve_threat table), c80c98af F2 (core/threat_intel.py enrich_cves/annotate/tier), 08acba60 F3 (intelligence._threat_tier enrichment-first + build_intelligence offline annotate, priority formula UNCHANGED), 888c292b F4 (opt-in _phase_threat not scope-gated + monitor/GUI parity), e9e8d90f F5 (report card + web /findings threat block + CSV columns), 64535490 doc sync. Single CVEStore cache (no new DB), derive-on-read enrichment, soft-degrade offline, client-safe (metadata about CVEs, no target traffic). Decisions: tier KEV->high/EPSS pct>=0.90->high/>=0.50->medium; priority only (KEV->SLA deferred); opt-in not under Scope Guard; TTL 24h. Verified: ruff clean, full pytest 2101 passed (1 Starlette warning), self-check 29 tabs. DEFERRED (not blockers): KEV->SLA tightening, timeline NEW_KEV event, KEV alert rule, findings-detail GUI badge.

*Confidence: 1 | Status: active | Created: 2026-06-28T02:25:54*

### Architecture invariants

Architecture invariants (breaking them = regression): (1) UI thin, logic in core/utils; (2) single task runner _start_task/_run_async, no manual QThreads in tabs; (3) single sources of truth: paths/settings=core/config.py+core/paths.py PathManager, secret rules=core/secret_scanner.py RULES, project scans=core/project.py, endpoints=utils/endpoint_index.py; (4) plugins add tabs/analyzers WITHOUT editing core; (5) frozen-aware paths via PathManager; (6) optional deps degrade softly; (7) keep backward compat of Projects/ layout, metadata.json, report.json, runner contracts.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T14:49:14 | Tags: `invariants`, `architecture`, `contracts`*

### KEV/EPSS Threat Intelligence Feed epic APPROVED by...

KEV/EPSS Threat Intelligence Feed epic APPROVED by user (2026-06-28). 4 decisions RESOLVED: (1) threat_tier mapping: kev=True->high; epss_percentile>=0.90->high; >=0.50->medium; else fallback to existing static _threat_tier (no regression); thresholds as named module constants. (2) MVP feeds PRIORITY only via threat_tier; KEV->SLA tightening DEFERRED (touches risk/SLA verdict, needs separate approval). (3) threat_feed phase = opt-in network metadata like osv/asn, NOT Scope-Guard active-gated (no target traffic; queries CISA KEV catalog + FIRST EPSS per-CVE). (4) cache TTL 24h for KEV catalog and EPSS, pruned by age in CVEStore. Architecture: NO new data model - cache extends existing CVEStore (data/cve_cache.db, CVE-keyed get/put_cve_threat), finding enrichment is derive-on-read via core/threat_intel.annotate; priority formula UNCHANGED (only feeds existing threat_tier input). KEV=CISA public domain, EPSS=FIRST.org free keyless; injectable transport like nvd_provider; offline-first, soft-degrade. Impl order F1 core/threat_feed.py (KEV+EPSS parsers+cache) -> F2 core/threat_intel.py (orchestrator+annotate+tier) -> F3 intelligence._threat_tier seam -> F4 opt-in _phase_threat in collection_runner + monitor parity -> F5 surfaces (report card/web/CSV/badge/opt alert). One feature at a time with tests + section-7 report. Code not started; awaiting 'go' for F1.

*Confidence: 1 | Status: active | Created: 2026-06-28T02:03:44*

### Workbench v2 FULLY COMPLETE incl. GUI+web+docs (al...

Workbench v2 FULLY COMPLETE incl. GUI+web+docs (all 3 follow-up items done after user override 'да делай'). Commits: edb9853c (GUI scenario selector + baseline compare/export in gui/tab_audit_runs.py + web read-parity /audit-runs,/audit-runs/{id},/audit-compare in remote/web_app.py + record_comparison 'compared' event in core/audit_compare.py), 821f4520 (doc sync CLAUDE.md/AGENTS.md/PROJECT_STATUS.txt/PROJECT_REPORT.md). GUI template-run advances only the template's phase subset; web read endpoints are pure derive-on-read (no event writes), only the GUI compare action logs 'compared'. Final verification: ruff clean, full pytest 2074 passed (1 Starlette warning), main.py --self-check 29 tabs. Whole Workbench v2 epic (F1-F5 + surfaces + docs) closed locally on master; no remote git. CLAUDE.md/AGENTS.md/PROJECT_STATUS/PROJECT_REPORT now reflect v1+v2 and count 2074.

*Confidence: 1 | Status: active | Created: 2026-06-28T01:24:08*

### KEV->SLA tightening follow-up IMPLEMENTED (approve...

KEV->SLA tightening follow-up IMPLEMENTED (approved separately by user; was decision #2 deferred from KEV/EPSS epic). core/findings_sla.py: THREAT_SLA_MULTIPLIER {high:0.25, medium:0.5}, floor semantics (window only shrinks), reads ONLY the cached KEV/EPSS threat block (NOT the static intelligence._threat_tier heuristic). sla_status now returns effective sla_days + base_sla_days + tightened_by (kev/epss/None); new optional threat_mult param threaded through sla_status/annotate/breached_count/sla_summary/sla_events. Self-gating: no threat block => plain severity window (zero change for un-enriched runs). Wiring: collection_runner._sync_findings threat_intel.annotate(active) before sla_summary (offline, cold cache = no-op). Tests added in tests/test_findings_sla.py (21 pass). ruff clean. Docs updated: ROADMAP closed section, CLAUDE.md + AGENTS.md status, PROJECT_STATUS.txt. NOT yet committed; full pytest running.

*Confidence: 1 | Status: active | Created: 2026-06-28T08:49:20*

---

## Goals

*Objectives, targets, and milestones to track progress.*

### User wants to move Advanced Site Analyzer toward p...

User wants to move Advanced Site Analyzer toward pentesting with Codex and Claude Code and create a fully working pentest multitool program; needs analysis, structure, roadmap, required tools, and implementation plan.

*Confidence: 1 | Status: active | Created: 2026-06-28T00:15:05*

### User decided to continue developing Client-Safe Pe...

User decided to continue developing Client-Safe Pentest Workbench while Claude Code rests. Codex should first prepare a plan/structure for persistent audit-run history, safe active checks, ROE/scope editor, audit report surface, and release packaging; wait for user approval before implementation.

*Confidence: 1 | Status: active | Created: 2026-06-27T18:33:20 | Tags: `client-safe-workbench`, `planning`, `roadmap`, `approval-required`*

### User assigned Codex release + UX hardening after C...

User assigned Codex release + UX hardening after Client-Safe Pentest Workbench: suppress noisy external CLI consoles, surface CLI errors in GUI/status/log, harden cookies.txt UX with format errors and secret masking, keep GUI thin via _run_async/_start_task, add targeted offline/headless tests, verify ruff/targeted pytest/self-check, and commit locally; protected core/project/config/paths/findings_store/asset_store files remain off-limits.

*Confidence: 1 | Status: active | Created: 2026-06-28T00:19:55 | Tags: `release-hardening`, `client-safe`, `gui-ux`, `external-tools`, `cookies`*

### User proposed adapting Cloudflare security-audit-s...

User proposed adapting Cloudflare security-audit-skill methodology into ASA as a future feature: Security Audit Run with phases Collect/Recon Snapshot, Finding Hunt, Validation/False Positive Check, Risk+Business Impact, Structured Findings JSON, Independent Verification/Evidence Check. Key ideas: adversarial validation by separate validator, structured schemas (asa_finding/audit_run/validation), quality gates, additive audit runs over lifecycle/timeline. Do not copy scanner/prompts directly; keep ASA evidence-based authorized desktop/ASM product. User asked to split work between Claude Code and Codex/worktrees.

*Confidence: 1 | Status: active | Created: 2026-06-27T16:38:16*

---

## Commitments

*Promises, obligations, and TODOs that need follow-through.*

*No memories of this type.*

---

## Preferences

*User and entity preferences for personalization.*

### Per-task report format and priorities

Working-style preferences (from project governance): after each task give a report - What was done / Files changed / Why this solution / Risks / Recommended next steps. Priority order: 1 Stability, 2 Scalability, 3 Maintainability, 4 Clean code, 5 New features; if a feature conflicts with stability, stability wins. For non-trivial tasks: present a plan BEFORE coding. Reports/docs in this project are written in Russian.

*Confidence: 1 | Status: active | Created: 2026-06-27T14:49:21 | Tags: `report-format`, `priorities`, `workflow`*

---

## Relationships

*Entity connections, team context, and collaboration patterns.*

*No memories of this type.*

---

## Context

*Session summaries, status updates, and conversation state.*

### Project purpose and maturity

Advanced Site Analyzer: desktop tool (Python 3.11+, PySide6/qtpy + Fluent-Widgets) for AUTHORIZED website security analysis: recon, subdomain enumeration, dynamic traffic/API capture, security audit (secrets, source maps, cookies, GraphQL), frontend cloning, media extraction. Maturity: evolving from Security Analyzer into a local ASM (Attack Surface Management) + CSM (Continuous Security Monitoring) platform. Findings-lifecycle/asset-inventory/timeline/monitoring/intelligence layers already exist.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T14:49:07 | Tags: `project-overview`, `asm`, `csm`, `security`*

### Memanto setup for this project

Memanto setup (this project): backend = cloud (Moorcheh); project agent = asa-claude (namespace memanto_agent_asa-claude); shared by TWO connected agents (Local): (1) claude-code - project-local CLAUDE.md managed block + .claude/settings.json SessionStart hook running memanto memory sync + env PYTHONIOENCODING=utf-8 + .claude/settings.local.json allow Bash(memanto:*) (gitignored) + .claude/skills/memanto/SKILL.md; (2) codex - AGENTS.md managed block + .agents/skills/memanto/SKILL.md, no SessionStart hook (Codex has no Claude hooks, sync manually). Both share the same MEMORY.md. API key in ~/.memanto/.env. Source code, .env and secrets intentionally NOT stored - only summaries, decisions, commands, known errors.

*Confidence: 0.9 | Status: active | Created: 2026-06-27T14:49:23 | Tags: `memanto`, `setup`, `integration`, `claude-code`, `codex`*

### Key directories map

Key directories: core/ = ALL business logic and engines (UI must not leak in); gui/ = thin mixin UI layer (tab_*.py mixins, background work via _start_task/_run_async only); utils/ = infra (sqlite_store, endpoint_index, subprocess_utils); plugins/ = external tab plugins; plugins/analyzers/ = analyzer plugins; tests/ = ~1794 offline/headless pytest. Project workspace layout: Projects/<domain>/scans/<ts>/ + metadata.json.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T14:49:11 | Tags: `repo-structure`, `directories`, `architecture`*

---

## Events

*Important conversations, milestones, and temporal occurrences.*

### Implemented Audit Runs GUI Rules of Engagement con...

Implemented Audit Runs GUI Rules of Engagement controls and safe-check selection in commit 5039078. The GUI now passes client_safe ROE and selected safe checks into audit run creation; headers_check no longer emits findings without provided headers evidence. Verified with targeted pytest for audit GUI/checks/scope/store/report/policies, ruff on changed files, and python main.py --self-check.

*Confidence: 1 | Status: active | Created: 2026-06-27T22:39:15 | Tags: `asa`, `client-safe`, `audit-gui`, `release-readiness`*

### Implemented W4 core audit report surface in commit...

Implemented W4 core audit report surface in commit baf61e0: added core/audit_report.py with deterministic JSON/Markdown/HTML renderers over canonical audit-run payloads, client_findings/review_findings/audit_summary helpers, and tests/test_audit_report.py. Rejected or quality-failed findings remain in appendix, not client-facing critical claims. Verification: 21 audit report/store/schema/workflow tests passed; ruff changed files passed; python main.py --self-check = 29 tabs.

*Confidence: 1 | Status: active | Created: 2026-06-27T18:37:52 | Tags: `client-safe-workbench`, `w4`, `audit-report`, `commit-baf61e0`, `tests`*

### Implemented independent audit evidence verificatio...

Implemented independent audit evidence verification in commit 8b4f111. Added core.audit_evidence.verify_evidence_refs for offline deterministic checking of finding refs, safe-check refs, and artifact paths with traversal protection; Audit Runs now stores evidence_check in the independent_verification phase. Verified with 84 targeted audit/timeline tests, ruff, and python main.py --self-check.

*Confidence: 1 | Status: active | Created: 2026-06-27T22:47:31 | Tags: `asa`, `client-safe`, `evidence`, `release-readiness`*

### Completed Stage 1 Client-Safe Pentest Workbench co...

Completed Stage 1 Client-Safe Pentest Workbench contract hardening in commit 1c5a5a1: added minimal pure/offline core contract modules audit_workflow, scope_policy, action_policy, finding_validation, finding_quality, audit_schema; added asa_audit_run/finding/validation schemas; added six edge-test files. Verification passed: 28 Stage 1 tests, 39 targeted scope+Stage tests, ruff on changed files, python main.py --self-check (28 tabs). Only MEMORY.md remains modified from MEMANTO.

*Confidence: 1 | Status: active | Created: 2026-06-27T17:14:17 | Tags: `client-safe-workbench`, `stage-1`, `commit-1c5a5a1`, `tests`, `release-readiness`*

### Implemented W2/W3 core foundation in commit 69af61...

Implemented W2/W3 core foundation in commit 69af61a: added core/audit_scope.py for ROE normalization/validation/summary/scope decisions and core/audit_checks.py for client-safe gated checks (headers, cookie flags, source map detection, non-destructive endpoint probe with injected fetcher only). Added tests/test_audit_scope.py and tests/test_audit_checks.py. Verification: 24 scope/check/action tests passed; ruff changed files passed; python main.py --self-check = 29 tabs.

*Confidence: 1 | Status: active | Created: 2026-06-27T18:42:24 | Tags: `client-safe-workbench`, `w2`, `w3`, `roe`, `safe-checks`, `commit-69af61a`*

### Release-readiness check for Client-Safe Pentest Wo...

Release-readiness check for Client-Safe Pentest Workbench passed after commits 5039078 and 98be523: targeted audit pytest suite reports 65 passed, ruff check on changed audit/core/gui/tests passed, and python main.py --self-check reports 29 tabs.

*Confidence: 1 | Status: active | Created: 2026-06-27T22:40:36 | Tags: `asa`, `client-safe`, `release-readiness`, `tests`*

### Implemented granular Client-Safe audit events in c...

Implemented granular Client-Safe audit events in commit 2ff3485. Audit Runs now records idempotent finding_verified/rejected/needs_review, quality_gate_passed/failed, and confidence_changed events into AuditRunStore; timeline can surface these through the existing audit-run integration. Verified with 85 targeted audit/timeline tests, ruff, and python main.py --self-check.

*Confidence: 1 | Status: active | Created: 2026-06-27T23:05:35 | Tags: `asa`, `client-safe`, `audit-events`, `timeline`, `release-readiness`*

### Stage 3 full release-readiness verification after ...

Stage 3 full release-readiness verification after Client-Safe Pentest Workbench Stage 1/2 commits: full pytest run with '-p no:cacheprovider --basetemp .pytest-full-stage3' passed 1913 tests with 1 existing Starlette/httpx warning in 364.10s; temp basetemp removed; code worktree clean except MEMANTO-managed MEMORY.md.

*Confidence: 1 | Status: active | Created: 2026-06-27T17:28:53 | Tags: `client-safe-workbench`, `stage-3`, `full-pytest`, `release-readiness`*

### Full release verification after GUI polish passed ...

Full release verification after GUI polish passed on 2026-06-27: ruff check . passed, python main.py --self-check reported 28 tabs, and pytest -p no:cacheprovider --basetemp .pytest_tmp_full_release completed with 1876 passed, 1 Starlette/httpx deprecation warning, exit code 0.

*Confidence: 1 | Status: active | Created: 2026-06-27T16:14:27*

### Final release-readiness after project bundle audit...

Final release-readiness after project bundle audit-run portability commit 904dd43 passed on 2026-06-28: ruff check . passed; full pytest with -p no:cacheprovider --basetemp .pytest-full-project-audit-bundles reported 2020 passed, 1 known Starlette/httpx warning in 535.99s; python main.py --self-check reported 29 tabs; PyInstaller build with QT_API=pyside6 succeeded; frozen dist/SiteAnalyzer.exe --self-check exited 0. No remote git actions.

*Confidence: 1 | Status: active | Created: 2026-06-27T23:49:12 | Tags: `asa`, `client-safe`, `project-io`, `release-readiness`, `full-pytest`, `frozen-smoke`*

### Overview/import-export UX audit completed in commi...

Overview/import-export UX audit completed in commit 922aab27: Overview load errors now clear stale portfolio rows, totals, heatmap, trend selector, company roll-up, assign combo, and company filter; tests use a lightweight OverviewHost to avoid full MainWindow teardown quirks. Verified with overview/project_io/dashboard/timeline/criticality/osint targeted tests, ruff, and main.py --self-check.

*Confidence: 1 | Status: active | Created: 2026-06-27T16:30:26*

### Final release-readiness after audit event commit 2...

Final release-readiness after audit event commit 2ff3485 passed on 2026-06-28: ruff check . passed; full pytest with -p no:cacheprovider --basetemp .pytest-full-audit-events reported 1948 passed, 1 known Starlette/httpx warning in 467.39s; python main.py --self-check reported 29 tabs; PyInstaller build with QT_API=pyside6 succeeded; frozen dist/SiteAnalyzer.exe --self-check exited 0. No remote git actions.

*Confidence: 1 | Status: active | Created: 2026-06-27T23:16:21 | Tags: `asa`, `client-safe`, `audit-events`, `release-readiness`, `full-pytest`, `frozen-smoke`*

### Codex completed an internal polish/release-readine...

Codex completed an internal polish/release-readiness pass in current worktree: hardened project_io import against unsafe manifest slug traversal/absolute paths; made optional feature summary/missing treat detector exceptions as unavailable; added hermetic self-check smoke with ASA_DATA_ROOT and tab-count assertion; added demo_seed CLI guardrail tests for non-empty dir and --force; added release-readiness tests pinning CI ruff/pytest/PyInstaller/self-check invariants. Targeted pytest passed: 50 tests across project_io/self_check/demo_seed/features/launcher/first_run/release_readiness; ruff passed on changed files.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T15:11:13 | Tags: `internal-polish`, `release-readiness`, `tests`, `project-io`*

### Frozen/PyInstaller smoke after Client-Safe Pentest...

Frozen/PyInstaller smoke after Client-Safe Pentest Workbench Stage 1/2 passed on 2026-06-27: PyInstaller 6.20.0 built dist/SiteAnalyzer.exe with 'pyinstaller build.spec --clean --noconfirm'; frozen exe self-check was run with QT_QPA_PLATFORM=offscreen and isolated ASA_DATA_ROOT and exited 0; exe size 71,624,165 bytes. Build log still warns hook-qtpy selected PyQt5 while PySide6 is also available, but runtime smoke passed. Code worktree clean except MEMANTO-managed MEMORY.md.

*Confidence: 1 | Status: active | Created: 2026-06-27T17:36:53 | Tags: `client-safe-workbench`, `frozen-smoke`, `pyinstaller`, `release-readiness`*

### Integrated persistent audit history and report exp...

Integrated persistent audit history and report exports into Audit Runs GUI in commit 666f7d4: Audit Runs now saves runs to AuditRunStore, loads per-project history, opens saved runs, exports JSON/Markdown/HTML via core audit_report, and tests isolate default audit_runs.db. Verification: 24 GUI/store/report tests passed, 48 extended audit GUI/self-check tests passed, ruff changed files passed, python main.py --self-check = 29 tabs.

*Confidence: 1 | Status: active | Created: 2026-06-27T18:40:28 | Tags: `client-safe-workbench`, `audit-history`, `gui`, `commit-666f7d4`, `tests`*

### Final release-readiness after Client-Safe Pentest ...

Final release-readiness after Client-Safe Pentest Workbench timeline/evidence work passed on 2026-06-28: ruff check . passed; full pytest with -p no:cacheprovider --basetemp .pytest-full-client-safe-final reported 1947 passed, 1 known Starlette/httpx warning in 564.43s; python main.py --self-check reported 29 tabs; PyInstaller build with QT_API=pyside6 succeeded and frozen dist/SiteAnalyzer.exe --self-check exited 0. Exe size 73,903,732 bytes. No remote git actions.

*Confidence: 1 | Status: active | Created: 2026-06-27T22:59:46 | Tags: `asa`, `client-safe`, `release-readiness`, `full-pytest`, `frozen-smoke`*

### Post-merge release-readiness after backend release...

Post-merge release-readiness after backend release-hardening merge fb862990 and Client-Safe Workbench commits passed on 2026-06-28: targeted smoke 72 passed; ruff check . passed; full pytest with -p no:cacheprovider --basetemp .pytest-full-post-merge reported 2020 passed, 1 known Starlette/httpx warning in 543.27s; python main.py --self-check reported 29 tabs; PyInstaller build with QT_API=pyside6 succeeded; frozen dist/SiteAnalyzer.exe --self-check exited 0. No remote git actions.

*Confidence: 1 | Status: active | Created: 2026-06-27T23:30:30 | Tags: `asa`, `post-merge`, `release-readiness`, `backend-hardening`, `client-safe`, `frozen-smoke`*

### Implemented project bundle portability for Client-...

Implemented project bundle portability for Client-Safe audit history in commit 904dd43. AuditRunStore now participates in row-level project export/import via PROJECT_EXPORT, and core.project_io includes audit_runs.json plus audit_run/audit_event counts. Round-trip tests now verify audit runs/events survive import with findings/assets/project tree. Verified with 73 targeted project/audit tests, ruff, and python main.py --self-check.

*Confidence: 1 | Status: active | Created: 2026-06-27T23:37:43 | Tags: `asa`, `client-safe`, `project-io`, `audit-runs`, `release-readiness`*

### Final verification after Codex release-readiness c...

Final verification after Codex release-readiness commits: ruff check . passed; full pytest summary reported 1862 passed, 1 known Starlette/httpx warning in 382.49s. Process still returned exit code 1 after green summary on Python 3.14/Windows, matching the observed shutdown/exit-code quirk rather than test failures. Commits created: 3afed1fd Harden release readiness checks; cd99bf09 Validate project bundle manifests; 696795d Report launcher runner failures.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T15:36:21 | Tags: `release-readiness`, `verification`, `commits`, `pytest`*

### Started Authorized Pentest Multitool / Mission Cen...

Started Authorized Pentest Multitool / Mission Center M1 foundation: updated ROADMAP_ASM_2.0.md with EPIC FUTURE, added pure/offline core/pentest_mission.py mission contract, added schemas/asa_pentest_mission.schema.json and audit_schema alias, added tests/test_pentest_mission.py. Verification: pytest tests/test_pentest_mission.py tests/test_audit_schema_edges.py = 12 passed; ruff check changed core/test files passed. Current folder lacks .git, so Codex could not create a local commit.

*Confidence: 1 | Status: active | Created: 2026-06-28T00:21:45*

### User asked Codex to prepare a direct Claude Code p...

User asked Codex to prepare a direct Claude Code prompt so Claude deeply understands the Authorized Pentest Multitool / Mission Center task and starts implementation without open-ended reasoning.

*Confidence: 1 | Status: active | Created: 2026-06-28T00:23:00*

### Codex added Stage 1 Client-Safe Pentest Workbench ...

Codex added Stage 1 Client-Safe Pentest Workbench edge-test harness files for audit workflow, scope/action policies, finding validation/quality, and audit schemas. Ruff on new tests passed. Targeted pytest is blocked at collection because core.audit_workflow, core.finding_validation, core.finding_quality, and core.audit_schema modules (and schemas/) are absent from current/local worktrees; Codex did not implement core contract due explicit boundary.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T17:05:38 | Tags: `client-safe-workbench`, `edge-tests`, `blocked-contract`, `ruff`*

### Implemented Client-Safe Pentest Workbench timeline...

Implemented Client-Safe Pentest Workbench timeline integration in commit 9679915. core.timeline now folds persisted AuditRunStore runs/events into the derived timeline as audit_run_started/completed/failed and audit_* events without a second findings source of truth. Verified with 81 targeted audit/timeline tests, ruff on changed files, and python main.py --self-check.

*Confidence: 1 | Status: active | Created: 2026-06-27T22:45:36 | Tags: `asa`, `client-safe`, `timeline`, `release-readiness`*

### Finalized Codex's uncommitted work in this worktre...

Finalized Codex's uncommitted work in this worktree (user authorized: Codex inactive). Two coherent complete units committed: c51c1ba2 external_tools.command_error SSOT (rc+stderr tail) wired into nuclei/katana/amass/subfinder/httpx/bbot; d988da0f cookies.txt validation in core/cookie_auditor.py (read/validate/describe_cookies_txt + CookieFileError + mask_cookie_value, never exposes raw values) + GUI preflight in tab_collection/tab_media. Verified: ruff clean, targeted tests green, full pytest already 2074 green with these present, self-check 29 tabs. Working tree now clean (only auto-synced MEMORY.md). My Workbench v2 commits stayed scoped; these Codex commits are separate.

*Confidence: 1 | Status: active | Created: 2026-06-28T01:29:56*

### GUI polish completed in commits 31094a23, b0ddfcc,...

GUI polish completed in commits 31094a23, b0ddfcc, 977e6e6, 47ab784, c2fe4f6: link helpers, settings dependency hint wrapping, and stale-state clearing for IaC, Remediation, Attack Paths, Exposure, Priorities, Technology Risk, and Scan Accuracy tabs. Targeted GUI tests, ruff, and main.py --self-check passed.

*Confidence: 1 | Status: active | Created: 2026-06-27T15:48:35*

---

## Learnings

*Knowledge acquired from experience, corrections, and insights.*

*No memories of this type.*

---

## Observations

*Patterns noticed, behavioral notes, and recurring themes.*

*No memories of this type.*

---

## Artifacts

*Tool outputs, files, reports, and external references.*

### Workbench v2 plan DRAFTED (awaiting human approval...

Workbench v2 plan DRAFTED (awaiting human approval, no code). Extends the CLOSED Client-Safe Pentest Workbench, never duplicates. Features: F1 audit scenario templates (core/audit_templates.py: light_client_safe/authenticated_review/evidence_refresh/release_regression; create_audit_run gains template/roe/baseline_run_id/auth_context, additive optional schema fields). F2 ROE/scope templates in core/audit_scope.py (passive_external/authenticated_internal/evidence_only/release_gate). F3 re-validation of unresolved findings (core/audit_revalidation.py: reads FindingsStore OPEN/IN_PROGRESS, excludes FIXED/IGNORED/FP, validation overlay only, lifecycle untouched). F4 Audit Run A/B compare (core/audit_compare.py + schemas/asa_audit_compare.schema.json: new/resolved/regressed/improved by finding_id, compare_gate, failed-phase=inconclusive, derive-on-read). F5 report surfaces JSON/MD/HTML extend core/audit_report.py, NO second findings source. Hard invariants: client_safe only, no exploit/bruteforce/auth-collection, single FindingsStore SoT, additive optional schema. 4 open decisions pending: default template, authenticated active scope, compare persistence (derive-on-read recommended), release-gate inconclusive rule.

*Confidence: 0.7 | Status: active | Created: 2026-06-28T00:26:32*

### Workbench v2 F1 DONE + committed (local, master). ...

Workbench v2 F1 DONE + committed (local, master). core/audit_templates.py = pure registry of 4 client-safe scenarios (light_client_safe/authenticated_review/evidence_refresh/release_regression) with list_templates/get_template/resolve_template. create_audit_run extended with keyword-only template/roe/baseline_run_id; bare call stays byte-identical to v1 (decision 1 honored), v2 keys recorded only when provided, ROE normalized via audit_scope.normalize_roe, lazy imports avoid circular dep. schemas/asa_audit_run.schema.json gained optional template/auth_context/baseline_run_id/roe/config. Decision: template selects a phase SUBSET (v1-consistent), not all-6-with-skipped. ROE-template name->dict binding deferred to F2. Verified: ruff clean, 55 targeted tests green (templates/workflow/store/schema/report/tab/timeline/project_io/scope/checks). NEXT: F2 ROE/scope templates in core/audit_scope.py.

*Confidence: 0.9 | Status: active | Created: 2026-06-28T00:34:25*

---

## Errors

*Failure records, bugs, and lessons learned from mistakes.*

### Full release-readiness verification after Codex in...

Full release-readiness verification after Codex internal polish: ruff check . passed; full pytest reported '1856 passed, 1 warning in 373.28s' with only the known Starlette/httpx warning, but process exit code was 1 after the green summary on Python 3.14/Windows. Treat as the known shutdown/exit-code quirk unless failures appear above the summary.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T15:25:11 | Tags: `pytest`, `python3.14`, `windows`, `release-readiness`*

### pytest exit 127 on Py3.14 is not a failure

Known trap: pytest may exit 127 on Python 3.14 at interpreter shutdown and drop the summary line. This is NOT a test failure - read the real pass/fail counts above the shutdown noise. For a clean run use a unique --basetemp and -p no:cacheprovider on Windows (temp/cache teardown quirks).

*Confidence: 0.95 | Status: active | Created: 2026-06-27T14:49:18 | Tags: `pytest`, `python3.14`, `windows`, `false-failure`*

### Observed and fixed Recon GUI crash: dynamic endpoi...

Observed and fixed Recon GUI crash: dynamic endpoint status may be None; gui.tab_recon now formats missing status as '-' and tests cover None/empty/non-numeric endpoint status.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T23:59:49*

### memanto cp1251 UnicodeEncodeError workaround

Known trap (Windows): memanto CLI commands with rich output crash with UnicodeEncodeError (charmap/cp1251 cannot encode the check-mark glyph) on a Russian-locale console. Workaround: set PYTHONIOENCODING=utf-8 before running any memanto command. The file writes still succeed before the print crashes, so integration can be verified via memanto connect list.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T14:49:20 | Tags: `memanto`, `windows`, `cp1251`, `encoding`, `workaround`*

---

*End of memory export.*
