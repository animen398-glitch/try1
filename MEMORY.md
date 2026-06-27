# Memory — asa-claude

> Generated: 2026-06-27 20:47:34  
> Total memories: **33**  
> Breakdown: instruction: 8, decision: 3, goal: 1, preference: 1, context: 3, event: 14, error: 3

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

### Roadmap updated in commit 3af7604 with EPIC FUTURE...

Roadmap updated in commit 3af7604 with EPIC FUTURE — Client-Safe Pentest Workbench: product frame, 6 Audit Run phases, core contracts, quality gate, additive runs, GUI Audit Runs, safe active checks, forbidden client-safe actions, Claude/Codex split, and DoD.

*Confidence: 1 | Status: active | Created: 2026-06-27T16:45:43*

### Backend release-hardening contracts (T1-T5)

Backend release-hardening contracts (branch backend/release-hardening, not yet merged): (1) SQLiteStore opens every connection with WAL journal_mode + synchronous=NORMAL + explicit busy_timeout (single const BUSY_TIMEOUT_MS) so concurrent monitor/GUI/web access no longer hits 'database is locked'; raw .db files are never copied (export/import is row-level) so WAL sidecars are safe. (2) A corrupt DB file on init is quarantined to <db>.corrupt-<ts> and recreated empty (never deletes data); a transient lock is NOT treated as corruption. (3) All 6 *_cli.py share core/cli_common.py (configure_stdout + CliError + run_main): expected failures become 'error: <msg>' on stderr + exit 2 instead of a traceback; in-process main(argv) unchanged. (4) remote/web_app.py has a global FastAPI exception handler returning a uniform JSON {'error': ...} 500 so the console's response.json() contract always holds. (5) Event ordering was audited and is already deterministic (findings/asset stores ORDER BY id; timeline stable sort) - no change made.

*Confidence: 0.9 | Status: active | Created: 2026-06-27T16:28:31 | Tags: `backend-hardening`, `sqlite-wal`, `cli-contract`, `web-error-envelope`, `release-readiness`*

### Architecture invariants

Architecture invariants (breaking them = regression): (1) UI thin, logic in core/utils; (2) single task runner _start_task/_run_async, no manual QThreads in tabs; (3) single sources of truth: paths/settings=core/config.py+core/paths.py PathManager, secret rules=core/secret_scanner.py RULES, project scans=core/project.py, endpoints=utils/endpoint_index.py; (4) plugins add tabs/analyzers WITHOUT editing core; (5) frozen-aware paths via PathManager; (6) optional deps degrade softly; (7) keep backward compat of Projects/ layout, metadata.json, report.json, runner contracts.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T14:49:14 | Tags: `invariants`, `architecture`, `contracts`*

---

## Goals

*Objectives, targets, and milestones to track progress.*

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

### Completed Stage 1 Client-Safe Pentest Workbench co...

Completed Stage 1 Client-Safe Pentest Workbench contract hardening in commit 1c5a5a1: added minimal pure/offline core contract modules audit_workflow, scope_policy, action_policy, finding_validation, finding_quality, audit_schema; added asa_audit_run/finding/validation schemas; added six edge-test files. Verification passed: 28 Stage 1 tests, 39 targeted scope+Stage tests, ruff on changed files, python main.py --self-check (28 tabs). Only MEMORY.md remains modified from MEMANTO.

*Confidence: 1 | Status: active | Created: 2026-06-27T17:14:17 | Tags: `client-safe-workbench`, `stage-1`, `commit-1c5a5a1`, `tests`, `release-readiness`*

### Stage 3 full release-readiness verification after ...

Stage 3 full release-readiness verification after Client-Safe Pentest Workbench Stage 1/2 commits: full pytest run with '-p no:cacheprovider --basetemp .pytest-full-stage3' passed 1913 tests with 1 existing Starlette/httpx warning in 364.10s; temp basetemp removed; code worktree clean except MEMANTO-managed MEMORY.md.

*Confidence: 1 | Status: active | Created: 2026-06-27T17:28:53 | Tags: `client-safe-workbench`, `stage-3`, `full-pytest`, `release-readiness`*

### Full release verification after GUI polish passed ...

Full release verification after GUI polish passed on 2026-06-27: ruff check . passed, python main.py --self-check reported 28 tabs, and pytest -p no:cacheprovider --basetemp .pytest_tmp_full_release completed with 1876 passed, 1 Starlette/httpx deprecation warning, exit code 0.

*Confidence: 1 | Status: active | Created: 2026-06-27T16:14:27*

### Overview/import-export UX audit completed in commi...

Overview/import-export UX audit completed in commit 922aab27: Overview load errors now clear stale portfolio rows, totals, heatmap, trend selector, company roll-up, assign combo, and company filter; tests use a lightweight OverviewHost to avoid full MainWindow teardown quirks. Verified with overview/project_io/dashboard/timeline/criticality/osint targeted tests, ruff, and main.py --self-check.

*Confidence: 1 | Status: active | Created: 2026-06-27T16:30:26*

### Codex completed an internal polish/release-readine...

Codex completed an internal polish/release-readiness pass in current worktree: hardened project_io import against unsafe manifest slug traversal/absolute paths; made optional feature summary/missing treat detector exceptions as unavailable; added hermetic self-check smoke with ASA_DATA_ROOT and tab-count assertion; added demo_seed CLI guardrail tests for non-empty dir and --force; added release-readiness tests pinning CI ruff/pytest/PyInstaller/self-check invariants. Targeted pytest passed: 50 tests across project_io/self_check/demo_seed/features/launcher/first_run/release_readiness; ruff passed on changed files.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T15:11:13 | Tags: `internal-polish`, `release-readiness`, `tests`, `project-io`*

### Frozen/PyInstaller smoke after Client-Safe Pentest...

Frozen/PyInstaller smoke after Client-Safe Pentest Workbench Stage 1/2 passed on 2026-06-27: PyInstaller 6.20.0 built dist/SiteAnalyzer.exe with 'pyinstaller build.spec --clean --noconfirm'; frozen exe self-check was run with QT_QPA_PLATFORM=offscreen and isolated ASA_DATA_ROOT and exited 0; exe size 71,624,165 bytes. Build log still warns hook-qtpy selected PyQt5 while PySide6 is also available, but runtime smoke passed. Code worktree clean except MEMANTO-managed MEMORY.md.

*Confidence: 1 | Status: active | Created: 2026-06-27T17:36:53 | Tags: `client-safe-workbench`, `frozen-smoke`, `pyinstaller`, `release-readiness`*

### Final verification after Codex release-readiness c...

Final verification after Codex release-readiness commits: ruff check . passed; full pytest summary reported 1862 passed, 1 known Starlette/httpx warning in 382.49s. Process still returned exit code 1 after green summary on Python 3.14/Windows, matching the observed shutdown/exit-code quirk rather than test failures. Commits created: 3afed1fd Harden release readiness checks; cd99bf09 Validate project bundle manifests; 696795d Report launcher runner failures.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T15:36:21 | Tags: `release-readiness`, `verification`, `commits`, `pytest`*

### Codex added Stage 1 Client-Safe Pentest Workbench ...

Codex added Stage 1 Client-Safe Pentest Workbench edge-test harness files for audit workflow, scope/action policies, finding validation/quality, and audit schemas. Ruff on new tests passed. Targeted pytest is blocked at collection because core.audit_workflow, core.finding_validation, core.finding_quality, and core.audit_schema modules (and schemas/) are absent from current/local worktrees; Codex did not implement core contract due explicit boundary.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T17:05:38 | Tags: `client-safe-workbench`, `edge-tests`, `blocked-contract`, `ruff`*

### GUI polish completed in commits 31094a23, b0ddfcc,...

GUI polish completed in commits 31094a23, b0ddfcc, 977e6e6, 47ab784, c2fe4f6: link helpers, settings dependency hint wrapping, and stale-state clearing for IaC, Remediation, Attack Paths, Exposure, Priorities, Technology Risk, and Scan Accuracy tabs. Targeted GUI tests, ruff, and main.py --self-check passed.

*Confidence: 1 | Status: active | Created: 2026-06-27T15:48:35*

### Completed Stage 2 Client-Safe Pentest Workbench GU...

Completed Stage 2 Client-Safe Pentest Workbench GUI in commit 9326ded: added thin gui/tab_audit_runs.py, registered Audit Runs tab in PluginManager/MainWindow, added AuditRunsHost and tests/test_audit_runs_tab.py. UI includes project selector, client_safe/scope display, Start Audit Run via _run_async, phase progress, validation/quality/confidence/evidence refs table, detail panel, deterministic JSON export. Verification passed: 36 Stage1+Audit GUI tests, 41 GUI/wiring tests, ruff changed files, python main.py --self-check (29 tabs).

*Confidence: 1 | Status: active | Created: 2026-06-27T17:20:51 | Tags: `client-safe-workbench`, `stage-2`, `gui`, `commit-9326ded`, `tests`*

### Final release-readiness sweep after Client-Safe Pe...

Final release-readiness sweep after Client-Safe Pentest Workbench work: full 'ruff check .' passed; build/ and dist/ are ignored artifacts; latest commits are 9326ded Add audit runs GUI tab and 1c5a5a1 Add client-safe audit contract hardening; git status clean for code with only MEMANTO-managed MEMORY.md modified.

*Confidence: 1 | Status: active | Created: 2026-06-27T17:38:23 | Tags: `client-safe-workbench`, `release-readiness`, `ruff`, `git-status`*

### Final frozen smoke rerun used explicit QT_API=pysi...

Final frozen smoke rerun used explicit QT_API=pyside6: 'pyinstaller build.spec --clean --noconfirm' selected PySide6 in hook-qtpy (no PyQt5 binding-selection warning), built dist/SiteAnalyzer.exe size 73,868,687 bytes, and frozen exe --self-check exited 0 with isolated ASA_DATA_ROOT. Temporary .frozen-smoke-data removed; build/ and dist/ remain ignored artifacts; code worktree clean except MEMANTO-managed MEMORY.md.

*Confidence: 1 | Status: active | Created: 2026-06-27T17:44:37 | Tags: `client-safe-workbench`, `frozen-smoke`, `qt-api-pyside6`, `release-readiness`*

### Packaging smoke audit passed on 2026-06-27: PyInst...

Packaging smoke audit passed on 2026-06-27: PyInstaller 6.20.0 built SiteAnalyzer.exe with 'pyinstaller build.spec --clean --noconfirm' under local Python 3.14.5; dist/SiteAnalyzer.exe size 71,602,118 bytes (68.29 MiB); frozen smoke 'dist/SiteAnalyzer.exe --self-check' with QT_QPA_PLATFORM=offscreen exited 0. Build log included qtpy multi-binding warning and optional missing-module warnings, but frozen self-check passed. build/ and dist/ are gitignored.

*Confidence: 1 | Status: active | Created: 2026-06-27T16:24:53*

### Second GUI polish wave completed in commits 0f02da...

Second GUI polish wave completed in commits 0f02da7, d55dcc0, 3c0fda7: stale-state clearing for lifecycle tabs (Assets, Findings, Criticality), Timeline, OSINT Catalog, and Dashboard table errors; added Timeline/Criticality lightweight test hosts to avoid Windows/offscreen MainWindow teardown exit-code quirks. Targeted GUI smoke (139 tests), ruff, and main.py --self-check passed.

*Confidence: 1 | Status: active | Created: 2026-06-27T16:01:40*

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

*No memories of this type.*

---

## Errors

*Failure records, bugs, and lessons learned from mistakes.*

### Full release-readiness verification after Codex in...

Full release-readiness verification after Codex internal polish: ruff check . passed; full pytest reported '1856 passed, 1 warning in 373.28s' with only the known Starlette/httpx warning, but process exit code was 1 after the green summary on Python 3.14/Windows. Treat as the known shutdown/exit-code quirk unless failures appear above the summary.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T15:25:11 | Tags: `pytest`, `python3.14`, `windows`, `release-readiness`*

### pytest exit 127 on Py3.14 is not a failure

Known trap: pytest may exit 127 on Python 3.14 at interpreter shutdown and drop the summary line. This is NOT a test failure - read the real pass/fail counts above the shutdown noise. For a clean run use a unique --basetemp and -p no:cacheprovider on Windows (temp/cache teardown quirks).

*Confidence: 0.95 | Status: active | Created: 2026-06-27T14:49:18 | Tags: `pytest`, `python3.14`, `windows`, `false-failure`*

### memanto cp1251 UnicodeEncodeError workaround

Known trap (Windows): memanto CLI commands with rich output crash with UnicodeEncodeError (charmap/cp1251 cannot encode the check-mark glyph) on a Russian-locale console. Workaround: set PYTHONIOENCODING=utf-8 before running any memanto command. The file writes still succeed before the print crashes, so integration can be verified via memanto connect list.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T14:49:20 | Tags: `memanto`, `windows`, `cp1251`, `encoding`, `workaround`*

---

*End of memory export.*
