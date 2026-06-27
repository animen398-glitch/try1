# Memory — asa-claude

> Generated: 2026-06-27 17:59:36  
> Total memories: **9**  
> Breakdown: instruction: 2, decision: 1, preference: 1, context: 3, error: 2

---

## Instructions

*Standing rules, constraints, and guidelines to always follow.*

### Install/run/test/lint commands

Commands: install dev deps = pip install -r requirements-dev.txt ; run tests = pytest (offline, headless Qt offscreen) ; run GUI = python main.py ; lint = ruff ; demo workspace = ASA_DATA_ROOT=<dir> python main.py (after demo_seed.py). All tests must stay offline (stub network/subprocess); never require real internet or external binaries.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T14:49:13 | Tags: `commands`, `build`, `test`, `lint`*

### Git policy and no-tech-debt rule

Git policy: local commits ARE the norm (Claude may commit verified pytest/ruff-clean units with meaningful messages; build artifacts dist/ build/ temp/ stay out per .gitignore). FORBIDDEN without explicit one-off user permission: git push/fetch/pull/clone, PRs, changing remote/origin, releases, any GitHub/remote action. Also forbidden: tech debt, hacks, stub-for-later, copy-paste logic, duplicate functionality, rewriting working code without need.

*Confidence: 1 | Status: active | Created: 2026-06-27T14:49:16 | Tags: `git-policy`, `rules`, `no-tech-debt`*

---

## Facts

*Verified information, project status, and established truths.*

*No memories of this type.*

---

## Decisions

*Architectural choices, approach selections, and their rationale.*

### Architecture invariants

Architecture invariants (breaking them = regression): (1) UI thin, logic in core/utils; (2) single task runner _start_task/_run_async, no manual QThreads in tabs; (3) single sources of truth: paths/settings=core/config.py+core/paths.py PathManager, secret rules=core/secret_scanner.py RULES, project scans=core/project.py, endpoints=utils/endpoint_index.py; (4) plugins add tabs/analyzers WITHOUT editing core; (5) frozen-aware paths via PathManager; (6) optional deps degrade softly; (7) keep backward compat of Projects/ layout, metadata.json, report.json, runner contracts.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T14:49:14 | Tags: `invariants`, `architecture`, `contracts`*

---

## Goals

*Objectives, targets, and milestones to track progress.*

*No memories of this type.*

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

*No memories of this type.*

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

### pytest exit 127 on Py3.14 is not a failure

Known trap: pytest may exit 127 on Python 3.14 at interpreter shutdown and drop the summary line. This is NOT a test failure - read the real pass/fail counts above the shutdown noise. For a clean run use a unique --basetemp and -p no:cacheprovider on Windows (temp/cache teardown quirks).

*Confidence: 0.95 | Status: active | Created: 2026-06-27T14:49:18 | Tags: `pytest`, `python3.14`, `windows`, `false-failure`*

### memanto cp1251 UnicodeEncodeError workaround

Known trap (Windows): memanto CLI commands with rich output crash with UnicodeEncodeError (charmap/cp1251 cannot encode the check-mark glyph) on a Russian-locale console. Workaround: set PYTHONIOENCODING=utf-8 before running any memanto command. The file writes still succeed before the print crashes, so integration can be verified via memanto connect list.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T14:49:20 | Tags: `memanto`, `windows`, `cp1251`, `encoding`, `workaround`*

---

*End of memory export.*
