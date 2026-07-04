# Memory — asa-claude

> Generated: 2026-07-03 21:01:17  
> Total memories: **81**  
> Breakdown: instruction: 8, decision: 25, goal: 8, commitment: 1, preference: 1, context: 3, event: 25, learning: 3, artifact: 3, error: 4

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

### Stage 14 DONE (commit 32729b20): Epic E1 increment...

Stage 14 DONE (commit 32729b20): Epic E1 increment 3 — keyed passive providers, COMPLETES E1. core/passive_osint.py: registry += shodan_api + censys (requires_key=True). parse_shodan_host/query_shodan (Shodan Host API api.shodan.io/shodan/host/{ip}?key=, flattens data[].cpe23/cpe + data[].vulns keys + top vulns to common {ip,ports,hostnames,cpes,tags,vulns}). parse_censys_host/query_censys (Censys Hosts v2 search.censys.io/api/v2/hosts/{ip} via HTTP Basic auth _fetch_basic base64 id:secret). All mirror InternetDB seam: injectable _fetch, never raise, soft-degrade to {} (empty key/creds->{}, invalid ip->{}). query_best(ip,*,config,fetch_map) prefers keyed when key set (shodan then censys) else keyless internetdb; keyed calls guarded (fall through on failure), FINAL internetdb call left BARE so scan phase backstop still catches artificial raises (=> E1 inc-2 scan tests UNCHANGED pass). config.py passive_osint += shodan_api_key/censys_api_id/censys_api_secret (empty=keyless default unchanged). collection_runner _phase_passive_osint: query_internetdb->query_best (1 line, byte-identical no-key). tests/test_passive_osint.py +9 (34 total). Zero target traffic, opt-in. Committed on strong targeted evidence (passive+scan+config green) while full suite b7axmq2ho backstop ran. E1 now fully done. Remaining depth: E3-2 scan IP enforcement, E4-2 render phase, E5-2 probe phase, E7-2 postgres dialect, E8-3 real runners+surface.

*Confidence: 0.95 | Status: active | Created: 2026-07-02T22:54:26*

### User decided external security tools remain indepe...

User decided external security tools remain independent third-party integrations; all CLI/binary execution from the ASA GUI must be invisible on Windows, with no cmd/conhost/PowerShell windows. Preserve the single utils.subprocess_utils run_hidden/popen_hidden seam and PyInstaller console=False.

*Confidence: 1 | Status: active | Created: 2026-07-03T17:52:19 | Tags: `external-tools`, `windows`, `subprocess`, `gui`*

### User approved implementation of the Client-Safe Pe...

User approved implementation of the Client-Safe Pentest Workbench development plan. Codex will start with W1 Persistent Audit Runs core slice: add audit_store and tests, no GUI yet, no protected project/config/path/findings/asset store edits.

*Confidence: 1 | Status: active | Created: 2026-06-27T18:34:22 | Tags: `client-safe-workbench`, `w1`, `audit-store`, `approved`*

### Planning direction proposed for Advanced Site Anal...

Planning direction proposed for Advanced Site Analyzer: evolve from ASM/CSM + Client-Safe Audit Runs into an Authorized Pentest Workbench by adding mission/scenario orchestration, tool adapters, evidence-first validation, ROE-gated active checks, operator profiles, lab mode, reporting, and plugin SDK; avoid stealth, brute force, destructive exploitation, and unscoped automation by default.

*Confidence: 0.95 | Status: active | Created: 2026-06-28T00:15:32*

### M2 (MissionStore persistence + project_io export) ...

M2 (MissionStore persistence + project_io export) APPROVED by user (2026-06-28, 'да'). D1-D5 as recommended: D1 MissionStore single-table NO events; D2 generalize SQLiteStore base for events-less PROJECT_EXPORT (events_table=None) - not phantom table, not override; D3 project_io FORMAT_VERSION stays 1 (additive missions.json); D4 missions columns mirror audit (+profile always client_safe); D5 GUI Overview Export/Import untouched (summary additive). Files: NEW core/mission_store.py (MissionStore mirror of AuditRunStore: missions table id/project/profile/status/payload/created_at/updated_at, save_mission via pentest_mission.mission_to_json+schema, get/list/delete/export_mission, PROJECT_EXPORT=('missions',None,None)), EDIT utils/sqlite_store.py (events_table None guard in export_project/import_project), EDIT core/project_io.py (missions.json mirror audit_runs.json + counts), EDIT tests/conftest.py (_isolate_missions_db), NEW tests/test_mission_store.py, EDIT tests/test_project_io.py (mission round-trip). M3+ deferred: timeline mission events, GUI tab, web parity.

*Confidence: 1 | Status: active | Created: 2026-06-28T12:29:49*

### Stage 13 DONE (commit 82c65e0d): Epic E8 increment...

Stage 13 DONE (commit 82c65e0d): Epic E8 increment 2 — JobStore/NodeStore + dispatcher. core/job_store.py: JobStore (queue) + NodeStore (explicit-node registry), each single-table SQLiteStore mirroring MissionStore; schema-validates payload (asa_job/asa_worker_node) before every write; JSON_FIELDS=(payload,). JobStore save_job(idempotent preserves created_at)/get_job/list_jobs(project,status; priority desc,created_at asc)/delete_job/claim_next_job(node). NodeStore save_node/get_node/list_nodes(authorized)/delete_node. core/job_dispatcher.py: run_job(job,runners,*,store,now) moves CLAIMED job running->completed|failed via INJECTED runner map, persists each step; missing runner or runner exception -> failed with transient _error (NOT raised, loop keeps draining); dispatch_next(node,runners,store)=claim+run; _pure() accepts pure job or store row. REVIEW BUG CAUGHT+FIXED: first cut passed store ROWS (job nested under payload, no top-level job_id/target) to pure scheduler claim_next which mis-normalized (fresh ids/empty targets), leaving original pending; fixed by extracting row['payload'] before scheduling. Touches NO existing file (E8 schemas already present); not wired to project_io (operational infra). Deferred: real-runner binding (collection/audit/mission/tool/retest adapters) + GUI/web/CLI surface. tests/test_job_store.py 14 green; contracts+sqlite_store+orchestration green.

*Confidence: 0.95 | Status: active | Created: 2026-07-02T22:27:32*

### Stage 6 DONE (commit 6418d1eb): E1 increment 2 — o...

Stage 6 DONE (commit 6418d1eb): E1 increment 2 — opt-in passive OSINT scan phase. collection_runner: passive_osint flag (ctor+configure) resolved via _passive_osint_enabled() which ALSO honours config passive_osint.enabled setting (no-GUI toggle, mirrors _scan_concurrency). _phase_passive_osint looks recon-resolved IP(s) up via query_internetdb (zero target traffic), rolls up ports/hostnames/CPEs/CVEs; Skipped on no-IP/no-data, Error backstop never sinks scan. Added to DAG (deps recon, NOT scope-gated like threat_feed) + _PHASE_ORDER (between asn_intel and osv) + HTML card; auto-appears in E2 Coverage Gate. asset_adapter.derive_assets folds passive_osint hosts/IPs/CPEs with source='passive_osint' (added LAST, first-wins dedup keeps native assets, correct per-phase GONE-gating). osint_to_assets got source= override. config passive_osint {enabled:False}. LOCKED DECISION: OSINT CVEs are intel-only, NOT promoted to FindingsStore (unverified CPE inferences, client-safe); osint_to_findings stays available for future keyed-provider increment. Off by default; seq<->concurrent equality holds; full suite green. Next Stage 7 = E1 increment 3 keyed Shodan API/Censys OR pivot to E6 Origin Exposure (correlate passive-OSINT IPs vs recon infra chain for CDN direct-IP leaks).

*Confidence: 0.95 | Status: active | Created: 2026-07-02T21:04:39*

### Stage 8 DONE (commit 554cdf12): Epic E3 Authorized...

Stage 8 DONE (commit 554cdf12): Epic E3 Authorized Network Execution Profiles (contract-first). New core/execution_profile.py (pure/offline, mirrors pentest_mission/engagement idiom): create/normalize/validate/ip_authorized/profile_expired/execution_profile_summary/to_json. Fields: allowed_ips/denied_ips (validated IP/CIDR via stdlib ipaddress, host-bits normalized via ip_network strict=False, invalid dropped), source_nodes (declared testing origin addresses for client allowlisting/auditability), legal {authorized_by,reference,contract_id,valid_from,valid_until,notes}. DEFAULT-DENY: empty allowlist authorizes nothing; denied_ips match wins over allowlist; malformed target IP denied. validate_execution_profile gates binding profile (non-empty allowlist + legal authorized_by+reference; malformed IP flagged). profile_expired compares ISO now vs legal.valid_until (lexicographic). schemas/asa_execution_profile.schema.json + audit_schema alias asa_execution_profile. Complements domain/action ROE (audit_scope) with IP+legal dimension — engagement schema had scope.allowed_ips as bare strings but no CIDR validation/membership/source-nodes/expiry. tests/test_execution_profile.py 19 green. DEFERRED increment 2: store + scan-time ip_authorized enforcement seam + GUI/config. Roadmap done: E2,E9,E10,E6,E3(contract),E1(inc1-2).

*Confidence: 0.95 | Status: active | Created: 2026-07-02T21:33:36*

### Workbench v2 epic COMPLETE + committed locally (ma...

Workbench v2 epic COMPLETE + committed locally (master, commits 86e473f1 F1, 859d8249 F2, 3175fcfa F3, 98b0fcc5 F4, ab7ce310 F5, roadmap doc). All 5 features implemented with tests: F1 core/audit_templates.py (4 scenarios), F2 ROE templates in core/audit_scope.py, F3 core/audit_revalidation.py (overlay, no lifecycle writes), F4 core/audit_compare.py + schemas/asa_audit_compare.schema.json (derive-on-read, failed phase=inconclusive), F5 compare+scenario renderers in core/audit_report.py. Verified: ruff clean, full pytest 2064 passed (1 known Starlette warning), main.py --self-check 29 tabs. Single FindingsStore SoT preserved, schema growth additive/optional, all client-safe. DEFERRED to Codex (contract-only): GUI selectors/buttons in gui/tab_audit_runs.py, remote/web_app.py read parity, optional persisted 'compared' event. Roadmap section 'EPIC CLOSED - Workbench v2' added. CLAUDE.md/AGENTS.md/PROJECT_STATUS.txt status banners NOT yet synced.

*Confidence: 1 | Status: active | Created: 2026-06-28T01:04:26*

### Stage 3 = Epic E9 Sensitive Data Governance DONE (...

Stage 3 = Epic E9 Sensitive Data Governance DONE (commit 9416e4c1). New core/data_governance.py (pure/offline render-time redaction reusing SSOTs — secret_scanner.RULES detection + finding_fingerprint.mask_value masking, prefix…len keeps vendor/type context). redact_text (group-aware so Bearer/api_key= keep label, idempotent), is_sensitive_key/redact_data (recursive non-mutating; only str values masked so match_count/auth_context int/bool safe), redact_finding/govern_rows. Wired at client-facing finding-table choke points (no-op on clean rows = byte-identical): finding_render.finding_md_table/finding_html_table (covers mission+engagement reports) + audit_report._md_table + inline HTML table(). Defense-in-depth (findings already masked at store time). Full suite green. Roadmap E2/E10/E9 done; remaining E1,E3-E8 larger integration features. Next options: wire E2 coverage into collection_runner live phase statuses, OR start E1 passive OSINT adapters.

*Confidence: 0.95 | Status: active | Created: 2026-07-02T16:42:10*

### User asked for a roadmap after an external review ...

User asked for a roadmap after an external review suggesting proxy rotation, passive OSINT, TLS/JA3 spoofing, smart wordlists, and PostgreSQL scaling. Codex should keep the plan client-safe: no stealth/WAF evasion/proxy rotation for bypass; reframe into authorized passive OSINT, coverage gates, transparent rate limits, allowlist-aware scanning, wordlist governance, and storage abstraction/scaling.

*Confidence: 1 | Status: active | Created: 2026-07-02T15:37:20 | Tags: `roadmap`, `client-safe`, `safety`, `passive-osint`, `scaling`*

### Backend release-hardening contracts (T1-T5)

Backend release-hardening (branch backend/release-hardening, ~23 commits, full-diff self-reviewed, awaiting external review/merge; not pushed). SQLite/stores: (1) SQLiteStore: every connection WAL + synchronous=NORMAL + busy_timeout (no 'database is locked'); raw .db never copied so WAL sidecars safe. (2) Corrupt DB on init quarantined to <db>.corrupt-<ts>, recreated empty (never deletes data); transient lock != corruption. (3) FindingsStore.sync/AssetStore.sync = ONE transaction (atomic) via _upsert/_set_status/_list_* (conn) workers behind thin public wrappers. (4) OperationRegistry bounds operations.db (newest MAX_HISTORY, prune every PRUNE_EVERY inserts); DataRegistry user data NOT auto-pruned. (5) CVEStore.prune bounds cve_cache.db by age + row cap; cve_intel.correlate prunes once per run (own store only). Contracts/IO: (6) all 6 *_cli.py share core/cli_common.py (configure_stdout+CliError+run_main): expected failures -> stderr 'error: <msg>' + exit 2. (7) remote/web_app.py global FastAPI handler -> uniform {'error':...} JSON 500; _job_results FIFO-capped + _log_queue maxsize drop-oldest. (8) CollectionRunner._persist_error_report always leaves a readable report.json (status Error) on finalization failure. (9) external_tools.run_command caps stdout (MAX_OUTPUT head, truncated flag). (10) utils/atomic_io.py (temp+os.replace) for ALL durable-state JSON: metadata+history, report.json, company registry, evidence_manifest, settings/targets (transient per-phase artifacts left direct). (11) Project.start_scan unique scan dir (mkdir exist_ok=False + -2/-3 suffix); runner takes scan_id from scan_dir.name. (12) Secret previews are a non-leaking mask: secret_scanner._preview = prefix(6)+ellipsis+length (mirrors mask_value, never the body) + dynamic_analyzer previews aligned. IMPORTANT: the length suffix is required - findings_adapter derives the secret discriminator from key:preview, so a too-short preview (prefix only) would merge two distinct same-prefix keys (e.g. two sk_live_ keys) into one finding; the length restores that entropy (caught in self-review). Audits, NO code change (some pinned by guard tests): event ordering deterministic; report consumers tolerant of thin/legacy/Error reports (test_report_backcompat); migration-with-data tested (test_findings_store_migration); secret redaction OK (operations.db/logs carry no secrets; raw only in local artifacts + LAN console, by-design); timestamps consistently local-naive, ct_history isolated naive-UTC, no mixed comparison, UTC migration intentionally not done. Remaining optional/deferred: cross-process advisory locking; roadmap-out-of-scope (live threat feeds, live cloud API, new scanners).

*Confidence: 0.9 | Status: active | Created: 2026-06-27T16:28:31 | Tags: `backend-hardening`, `sqlite-wal`, `atomic-sync`, `atomic-writes`, `cli-contract`, `web-error-envelope`, `retention`, `scan-dir-unique`, `secret-redaction`, `diff-reviewed`, `release-readiness`*

### KEV/EPSS Threat Intelligence Feed epic COMPLETE + ...

KEV/EPSS Threat Intelligence Feed epic COMPLETE + committed locally (master). Commits: 3017251f F1 (core/threat_feed.py KEV+EPSS parsers + CVEStore.cve_threat table), c80c98af F2 (core/threat_intel.py enrich_cves/annotate/tier), 08acba60 F3 (intelligence._threat_tier enrichment-first + build_intelligence offline annotate, priority formula UNCHANGED), 888c292b F4 (opt-in _phase_threat not scope-gated + monitor/GUI parity), e9e8d90f F5 (report card + web /findings threat block + CSV columns), 64535490 doc sync. Single CVEStore cache (no new DB), derive-on-read enrichment, soft-degrade offline, client-safe (metadata about CVEs, no target traffic). Decisions: tier KEV->high/EPSS pct>=0.90->high/>=0.50->medium; priority only (KEV->SLA deferred); opt-in not under Scope Guard; TTL 24h. Verified: ruff clean, full pytest 2101 passed (1 Starlette warning), self-check 29 tabs. DEFERRED (not blockers): KEV->SLA tightening, timeline NEW_KEV event, KEV alert rule, findings-detail GUI badge.

*Confidence: 1 | Status: active | Created: 2026-06-28T02:25:54*

### Stage 5 increment 1 DONE (commit 7a642a79): starte...

Stage 5 increment 1 DONE (commit 7a642a79): started Epic E1 Passive OSINT Layer contract-first. New core/passive_osint.py (pure/offline, mirrors update_check/threat_feed injectable _fetch HTTPS-only never-raises seam). PassiveSource registry PASSIVE_SOURCES + list_sources (keyless-first). First provider = Shodan InternetDB internetdb.shodan.io/{ip} — KEYLESS, ZERO TARGET TRAFFIC (reads Shodan's DB by IP, no packet to target). query_internetdb validates IP locally (non-IP never fetches), parse_internetdb normalizes ports/hostnames/cpes/tags/vulns. osint_to_assets/osint_to_findings map to canonical asset_adapter.Asset + findings_adapter.from_raw (CVE canonical identity for dedup, Info severity + passive/unverified detail). NO store writes, NO risk impact, NO existing file touched, NO new dep. tests/test_passive_osint.py 14 green. Next Stage 6 = E1 increment 2 opt-in scan wiring (passive_osint.enabled off-by-default, enrich synced IP assets, feed _sync_assets + E2 coverage as new phase). Then increment 3 keyed Shodan API/Censys behind configured keys. Roadmap DOCS_DEVELOPMENT_PLAYBOOK.md: E2/E10/E9 done, E1 in progress.

*Confidence: 0.95 | Status: active | Created: 2026-07-02T17:12:40*

### Added GUI table pagination in try1 (gap #3). gui/u...

Added GUI table pagination in try1 (gap #3). gui/ui_components.TablePaginator — UI windowing (the slow part is populating QTableWidget, not holding rows; data layer untouched). set_rows(full list) renders one page via render_row(table,row,rec) callback; control strip First/◀/▶/Last + 'стр X/Y · показано a–b из N' + page-size combo 100/200/500/1000; record_at(table_row)/index_at map table row -> full-list record for selection; on_page_changed clears stale detail. Applied to 3 highest-volume tables: Findings, Assets, Timeline — each keeps full list (_findings_records/_assets_records/_timeline_events_data) for selection+CSV, renders only a page; selection handlers use paginator.record_at. Remaining ~17 table tabs are trivial follow-up on same helper. Decision: UI windowing not store limit/offset (sorting/filter/CSV stay over full list). Commit e8d1df4d. Tests test_ui_pagination.py + findings selection-mapping. Remaining gaps: i18n, e2e/GUI tests, captured-scan->tool-evidence bridge, finding assignment/comments triage.

*Confidence: 1 | Status: active | Created: 2026-06-30T16:36:13*

### Closed Scan Retention & Backup epic in try1 (chose...

Closed Scan Retention & Backup epic in try1 (chosen after web-console-auth). Phase 1 retention: core/retention.py plan_retention(project,*,keep_last,keep_days,now) pure planner (always keep newest; keep_last/keep_days policy; no policy=keep all) + apply_retention deletes ONLY scans/<id>/ dir + marks metadata entry artifacts_pruned (index + history/<id>.json kept -> risk series intact, timeline degrades softly, findings never orphaned since scan_id is just a label); idempotent; policy_from_settings()/prune_project(). retention {enabled,keep_last,keep_days} in DEFAULT_SETTINGS off by default. collection_runner auto-prunes after Full Collection when enabled (best-effort). Overview 'Prune old scans' button. Decision (user): prune artifacts-only keep index. Commit db0aa9e3, tests/test_retention.py. Phase 2 backup: core/backup.py create_backup(dest,*,data_root=None,workspace=None) -> timestamped .zip; every *.db via sqlite online backup (WAL-safe, no sidecars) under data_root/, other files verbatim, workspace (Projects from output_dir) under workspace/ (skip if nested). backup_info reads manifest; restore_backup zip-slip guarded, skips existing unless replace=True. Overview 'Backup all…'/'Restore…' buttons. Stdlib only. Commit dd99e75e, tests/test_backup.py. Remaining gaps: GUI table pagination, i18n, e2e/GUI tests, captured-scan->tool-evidence bridge, finding assignment/comments triage.

*Confidence: 1 | Status: active | Created: 2026-06-30T16:03:28*

### Architecture invariants

Architecture invariants (breaking them = regression): (1) UI thin, logic in core/utils; (2) single task runner _start_task/_run_async, no manual QThreads in tabs; (3) single sources of truth: paths/settings=core/config.py+core/paths.py PathManager, secret rules=core/secret_scanner.py RULES, project scans=core/project.py, endpoints=utils/endpoint_index.py; (4) plugins add tabs/analyzers WITHOUT editing core; (5) frozen-aware paths via PathManager; (6) optional deps degrade softly; (7) keep backward compat of Projects/ layout, metadata.json, report.json, runner contracts.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T14:49:14 | Tags: `invariants`, `architecture`, `contracts`*

### Stage 4 DONE (commit f5bd357a): wired E2 Coverage ...

Stage 4 DONE (commit f5bd357a): wired E2 Coverage Gate to LIVE Full-Collection phase statuses (real per-scan coverage, not just audit-run fallback). New coverage.coverage_from_scan_report(report) maps report['phases'] outcomes (Success->full, Error->failed/failed_phase, Skipped->skipped classified scope_denied via scope_guard / missing_dependency via reason hints / else skipped_phase); never raises, truncates detail. collection_runner._build_coverage attaches report['coverage'] after _build_osint_catalog (best-effort, risk verdict untouched) + HTML 'Limitations & Coverage' card (wraps render_coverage_html in card-styled section to avoid double h2). report_export.report_markdown appends coverage section (from report['coverage'] or derived). tests in test_coverage.py. Full suite green. Roadmap E2/E10/E9 fully done incl E2 live wiring. Next Stage 5 = E1 Passive OSINT (keyless Shodan/Censys/Cert-log adapters, zero target traffic, opt-in, injectable _fetch seam like update_check/threat_feed, feed existing asset/finding adapters not new store).

*Confidence: 0.95 | Status: active | Created: 2026-07-02T17:07:47*

### KEV/EPSS Threat Intelligence Feed epic APPROVED by...

KEV/EPSS Threat Intelligence Feed epic APPROVED by user (2026-06-28). 4 decisions RESOLVED: (1) threat_tier mapping: kev=True->high; epss_percentile>=0.90->high; >=0.50->medium; else fallback to existing static _threat_tier (no regression); thresholds as named module constants. (2) MVP feeds PRIORITY only via threat_tier; KEV->SLA tightening DEFERRED (touches risk/SLA verdict, needs separate approval). (3) threat_feed phase = opt-in network metadata like osv/asn, NOT Scope-Guard active-gated (no target traffic; queries CISA KEV catalog + FIRST EPSS per-CVE). (4) cache TTL 24h for KEV catalog and EPSS, pruned by age in CVEStore. Architecture: NO new data model - cache extends existing CVEStore (data/cve_cache.db, CVE-keyed get/put_cve_threat), finding enrichment is derive-on-read via core/threat_intel.annotate; priority formula UNCHANGED (only feeds existing threat_tier input). KEV=CISA public domain, EPSS=FIRST.org free keyless; injectable transport like nvd_provider; offline-first, soft-degrade. Impl order F1 core/threat_feed.py (KEV+EPSS parsers+cache) -> F2 core/threat_intel.py (orchestrator+annotate+tier) -> F3 intelligence._threat_tier seam -> F4 opt-in _phase_threat in collection_runner + monitor parity -> F5 surfaces (report card/web/CSV/badge/opt alert). One feature at a time with tests + section-7 report. Code not started; awaiting 'go' for F1.

*Confidence: 1 | Status: active | Created: 2026-06-28T02:03:44*

### Workbench v2 FULLY COMPLETE incl. GUI+web+docs (al...

Workbench v2 FULLY COMPLETE incl. GUI+web+docs (all 3 follow-up items done after user override 'да делай'). Commits: edb9853c (GUI scenario selector + baseline compare/export in gui/tab_audit_runs.py + web read-parity /audit-runs,/audit-runs/{id},/audit-compare in remote/web_app.py + record_comparison 'compared' event in core/audit_compare.py), 821f4520 (doc sync CLAUDE.md/AGENTS.md/PROJECT_STATUS.txt/PROJECT_REPORT.md). GUI template-run advances only the template's phase subset; web read endpoints are pure derive-on-read (no event writes), only the GUI compare action logs 'compared'. Final verification: ruff clean, full pytest 2074 passed (1 Starlette warning), main.py --self-check 29 tabs. Whole Workbench v2 epic (F1-F5 + surfaces + docs) closed locally on master; no remote git. CLAUDE.md/AGENTS.md/PROJECT_STATUS/PROJECT_REPORT now reflect v1+v2 and count 2074.

*Confidence: 1 | Status: active | Created: 2026-06-28T01:24:08*

### KEV->SLA tightening follow-up IMPLEMENTED (approve...

KEV->SLA tightening follow-up IMPLEMENTED (approved separately by user; was decision #2 deferred from KEV/EPSS epic). core/findings_sla.py: THREAT_SLA_MULTIPLIER {high:0.25, medium:0.5}, floor semantics (window only shrinks), reads ONLY the cached KEV/EPSS threat block (NOT the static intelligence._threat_tier heuristic). sla_status now returns effective sla_days + base_sla_days + tightened_by (kev/epss/None); new optional threat_mult param threaded through sla_status/annotate/breached_count/sla_summary/sla_events. Self-gating: no threat block => plain severity window (zero change for un-enriched runs). Wiring: collection_runner._sync_findings threat_intel.annotate(active) before sla_summary (offline, cold cache = no-op). Tests added in tests/test_findings_sla.py (21 pass). ruff clean. Docs updated: ROADMAP closed section, CLAUDE.md + AGENTS.md status, PROJECT_STATUS.txt. NOT yet committed; full pytest running.

*Confidence: 1 | Status: active | Created: 2026-06-28T08:49:20*

### Added tool-evidence surface wiring in try1 (follow...

Added tool-evidence surface wiring in try1 (follow-up to the bridge). core/tool_evidence.evidence_from_project_scan(project, tool, *, base=None, scan_id=None) — thin I/O loader (mirrors timeline.build_timeline) resolving project scan report (latest or explicit) via ProjectStore/load_scan_report then delegating to pure evidence_from_report; {} on missing, never raises; base defaults to settings output_dir. GUI Missions 'Run tool' panel: new «Из скана» button (btn_mission_tool_evidence) -> off-thread _do_fill_tool_evidence(project,tool)=evidence_from_project_scan -> _on_tool_evidence_filled fills mission_tool_evidence QPlainTextEdit with pretty JSON (operator reviews/edits then Run; manual flow untouched; button enabled with run button). Web POST /missions/{id}/tools/run gains from_scan:bool + optional scan_id; when set and no evidence given, _mission_run_tool pulls evidence via evidence_from_project_scan(base=_REPORT_BASE) before run. Decision (user): GUI fill-button (transparent) not auto-checkbox. Commit e64618e9. Tests test_tool_evidence.py(loader)/test_missions_tab.py(fill worker)/test_web_missions.py(from_scan->completed+assets). Remaining gaps: i18n, e2e/GUI tests, pagination of remaining tables, more tool-evidence extractors (header/cookie/dependency).

*Confidence: 1 | Status: active | Created: 2026-06-30T18:56:16*

### Stage 2 = Epic E10 Parser Hardening DONE (commit 8...

Stage 2 = Epic E10 Parser Hardening DONE (commit 8f1608e9). New core/safe_parse.py (pure/offline/stdlib): ParseLimitError(ValueError) so degrade-not-raise handlers unchanged; configurable limits MAX_JSON_BYTES/DEPTH/ITEMS + MAX_MEMBER_BYTES with per-call overrides; json_nesting_depth (linear recursion-free string-aware, rejects JSON bombs pre-parse via regex string-strip); count_elements iterative (no RecursionError); safe_json_loads/read_bytes/read_text/read_json; safe_zip_read/zip_json/member_within_limit (zip-bomb guard on declared uncompressed size). Wired into untrusted seams: project.load_scan_report->safe_read_json (degrades to None), project_io import (manifest+DB-slice members via safe_zip_json, _safe_extract per-member size guard complementing zip-slip). iac_scanner left as-is (already had _MAX_FILE_BYTES). tests/test_safe_parse.py green; full suite exit 0. Next Stage 3 = E9 Sensitive Data Governance (redact secrets in client reports, reuse secret_scanner SSOT).

*Confidence: 0.95 | Status: active | Created: 2026-07-02T16:14:29*

---

## Goals

*Objectives, targets, and milestones to track progress.*

### User reaffirmed on 2026-07-01 that Advanced Site A...

User reaffirmed on 2026-07-01 that Advanced Site Analyzer should continue moving toward an authorized pentest project; recommended direction is client-safe pentest workbench with ROE/scope, evidence-first validation, tool orchestration, reporting, and guardrails rather than destructive exploitation/bruteforce/stealth automation.

*Confidence: 1 | Status: active | Created: 2026-06-30T22:02:30 | Tags: `pentest`, `client-safe`, `roadmap`, `asa`*

### User reaffirmed on 2026-07-01 that Advanced Site A...

User reaffirmed on 2026-07-01 that Advanced Site Analyzer should continue moving toward an authorized pentest project; recommended direction is client-safe pentest workbench with ROE/scope, evidence-first validation, tool orchestration, reporting, and guardrails rather than destructive exploitation/bruteforce/stealth automation.

*Confidence: 1 | Status: active | Created: 2026-06-30T22:02:17 | Tags: `pentest`, `client-safe`, `roadmap`, `asa`*

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

### User asked to split the remaining Advanced Site An...

User asked to split the remaining Advanced Site Analyzer work between Claude Code and Codex and prepare direct prompts for both agents. Proposed split should keep Claude on architecture/core contracts and Codex on release baseline, UX polish, tests, and thin surfaces.

*Confidence: 1 | Status: active | Created: 2026-06-28T11:57:40 | Tags: `asa`, `claude-code`, `codex`, `planning`*

### User asked Codex to analyze Advanced Site Analyzer...

User asked Codex to analyze Advanced Site Analyzer's remaining open gestalts and propose a plan before continuing implementation; next work should wait for user's chosen direction/approval.

*Confidence: 1 | Status: active | Created: 2026-06-28T11:54:24 | Tags: `asa`, `planning`, `next-step`*

---

## Commitments

*Promises, obligations, and TODOs that need follow-through.*

### User requested a full current-state report of Adva...

User requested a full current-state report of Advanced Site Analyzer in one TXT document for sharing with other AI reviewers.

*Confidence: 1 | Status: active | Created: 2026-07-02T15:17:01 | Tags: `report`, `review`, `project-status`*

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

### Added web parity for tool runs in try1 (remote/web...

Added web parity for tool runs in try1 (remote/web_app.py): _mission_run_tool(mission_id, tool, evidence) + POST /missions/{id}/tools/run (body {tool, evidence}, MissionToolRequest model) mirroring the Missions-tab Run tool surface. Synthetic scan_id=tool-<name>-<ts>, returns {mission_id, tool, status, written, findings, assets}; 404 unknown mission, 400 missing tool; blocked/skipped → 200 written:false (gated outcome, not error). Calls core.tool_runner.run_tool_for_mission; operator supplies captured evidence, tool never executed, gated by mission ROE, completed ingests into project stores. Tests in test_web_missions.py (4 helper + TestClient endpoint). Committed 44731ae3. Tool layer now full: contract->parsers->pipeline->bridge->report->ingest-store->runner->GUI(Missions)+web.

*Confidence: 1 | Status: active | Created: 2026-06-30T13:06:46*

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

### Codex hardened project bundle database-slice impor...

Codex hardened project bundle database-slice imports in commit 243dc1d9. SQLiteStore.validate_project_import now rejects main rows belonging to a foreign project, event rows referencing ids outside the imported slice, and events in single-table stores. core.project_io preflights findings/assets/audit/mission slices before deleting or extracting the project tree, so a tampered bundle cannot leave a partial destination tree. Verified: targeted storage/project tests passed, ruff clean, main.py --self-check 29 tabs, full pytest 2181 passed with 1 known Starlette/httpx warning. No remote git actions.

*Confidence: 1 | Status: active | Created: 2026-06-28T14:01:04 | Tags: `asa`, `project-bundle`, `sqlite-integrity`, `commit-243dc1d9`*

### Codex completed an internal polish/release-readine...

Codex completed an internal polish/release-readiness pass in current worktree: hardened project_io import against unsafe manifest slug traversal/absolute paths; made optional feature summary/missing treat detector exceptions as unavailable; added hermetic self-check smoke with ASA_DATA_ROOT and tab-count assertion; added demo_seed CLI guardrail tests for non-empty dir and --force; added release-readiness tests pinning CI ruff/pytest/PyInstaller/self-check invariants. Targeted pytest passed: 50 tests across project_io/self_check/demo_seed/features/launcher/first_run/release_readiness; ruff passed on changed files.

*Confidence: 0.95 | Status: active | Created: 2026-06-27T15:11:13 | Tags: `internal-polish`, `release-readiness`, `tests`, `project-io`*

### Frozen/PyInstaller smoke after Client-Safe Pentest...

Frozen/PyInstaller smoke after Client-Safe Pentest Workbench Stage 1/2 passed on 2026-06-27: PyInstaller 6.20.0 built dist/SiteAnalyzer.exe with 'pyinstaller build.spec --clean --noconfirm'; frozen exe self-check was run with QT_QPA_PLATFORM=offscreen and isolated ASA_DATA_ROOT and exited 0; exe size 71,624,165 bytes. Build log still warns hook-qtpy selected PyQt5 while PySide6 is also available, but runtime smoke passed. Code worktree clean except MEMANTO-managed MEMORY.md.

*Confidence: 1 | Status: active | Created: 2026-06-27T17:36:53 | Tags: `client-safe-workbench`, `frozen-smoke`, `pyinstaller`, `release-readiness`*

### Repaired Claude Code CLI on Windows: global npm pa...

Repaired Claude Code CLI on Windows: global npm package was absent despite correct PATH. Reinstalled official @anthropic-ai/claude-code globally; cmd.exe now resolves claude and reports version 2.1.200.

*Confidence: 1 | Status: active | Created: 2026-07-03T18:00:32 | Tags: `claude-code`, `windows`, `npm`, `repair`*

### Integrated persistent audit history and report exp...

Integrated persistent audit history and report exports into Audit Runs GUI in commit 666f7d4: Audit Runs now saves runs to AuditRunStore, loads per-project history, opens saved runs, exports JSON/Markdown/HTML via core audit_report, and tests isolate default audit_runs.db. Verification: 24 GUI/store/report tests passed, 48 extended audit GUI/self-check tests passed, ruff changed files passed, python main.py --self-check = 29 tabs.

*Confidence: 1 | Status: active | Created: 2026-06-27T18:40:28 | Tags: `client-safe-workbench`, `audit-history`, `gui`, `commit-666f7d4`, `tests`*

### Final release-readiness after Client-Safe Pentest ...

Final release-readiness after Client-Safe Pentest Workbench timeline/evidence work passed on 2026-06-28: ruff check . passed; full pytest with -p no:cacheprovider --basetemp .pytest-full-client-safe-final reported 1947 passed, 1 known Starlette/httpx warning in 564.43s; python main.py --self-check reported 29 tabs; PyInstaller build with QT_API=pyside6 succeeded and frozen dist/SiteAnalyzer.exe --self-check exited 0. Exe size 73,903,732 bytes. No remote git actions.

*Confidence: 1 | Status: active | Created: 2026-06-27T22:59:46 | Tags: `asa`, `client-safe`, `release-readiness`, `full-pytest`, `frozen-smoke`*

### Mission Center M2 IMPLEMENTED (persistence + proje...

Mission Center M2 IMPLEMENTED (persistence + project_io bundle). NEW core/mission_store.py: MissionStore(SQLiteStore) mirroring AuditRunStore but SINGLE-TABLE (mission has no event log in M1) - missions table (id/project/profile/status/payload/created_at/updated_at); save_mission normalizes+schema-validates via pentest_mission.mission_to_json before write (idempotent, created_at preserved); get/list/delete/export_mission; PROJECT_EXPORT=('missions',None,None). EDITED utils/sqlite_store.py: export_project/import_project now tolerate events_table=None (single-table slice, events:[]/events:0); 3-tuple path unchanged. EDITED core/project_io.py: bundle gains missions.json (mirror audit_runs.json) + missions count; FORMAT_VERSION stays 1 (backward-compat - old bundle without missions.json imports as 0). EDITED tests/conftest.py (_isolate_missions_db). NEW tests/test_mission_store.py (11), EDITED tests/test_project_io.py (+2 mission round-trip + legacy bundle). Decisions D1-D5 as approved. Full pytest 2177 green, ruff clean. Docs synced (ROADMAP M2 section, CLAUDE/AGENTS/PROJECT_STATUS/PROJECT_REPORT). NOT yet committed. M3+ deferred: timeline mission events, GUI Mission Center tab, web read parity. REMINDER: working tree still has FOREIGN uncommitted changes (demo_seed.py, gui/tab_iac.py, tests/test_demo_seed.py, tests/test_iac_tab.py) NOT mine - left untouched.

*Confidence: 1 | Status: active | Created: 2026-06-28T12:43:43*

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

---

## Learnings

*Knowledge acquired from experience, corrections, and insights.*

### IMPORTANT correction in try1: user asked to 'gener...

IMPORTANT correction in try1: user asked to 'generate 3 turnkey modules' (cloud_classifier, attack_paths engine, attack-surface GUI) but ALL THREE already existed — core/cloud_classifier.py (classify_cloud(provider,asn_name,asn,technologies,cname) — already consumes CNAME+CDN-tech signals), intelligence.build_attack_paths+correlation.py (entry/pivot/target/score/vector/band, shared-ip/subnet/asn clusters via ipaddress, blast radius), gui/tab_attack_paths.py (table+detail+async). Refused to duplicate (CLAUDE §5.2/5.3/6/10); audited + reported overlap; user chose to build only the genuinely-missing piece. Added gui/attack_graph_view.AttackGraphView(QGraphicsView): deterministic LAYERED Entry→Pivot→Targets node-edge graph (stdlib Qt, no graph lib), entry colored by severity, critical goal highlighted, targets capped MAX_TARGETS=12 + '+N more' overflow, node_clicked(node_id,role) signal, pure presentation over a loaded path record, headless-safe. Wired into tab_attack_paths below the table (select->render, node-click->detail, reload->clear), reuses load_attack_paths+_run_async. Commit 651c214f. tests test_attack_graph_view.py(6)+test_attack_paths_tab.py(+2). Lesson: always audit core/ before building 'new' modules — much ASM attack-path/cloud/correlation surface already exists.

*Confidence: 1 | Status: active | Created: 2026-06-30T17:02:51*

### Added header_audit + cookie_audit extractors to co...

Added header_audit + cookie_audit extractors to core/tool_evidence.EXTRACTORS in try1. header_audit: {url, headers} from recon.data.security_headers (gated on key present = recon fetched; headers_check flags missing). cookie_audit: {url, cookies} from cookies-phase data.cookies (CookieAuditor.audit rows have name/secure/httponly = exactly cookie_flags_check shape). dependency_auditor DELIBERATELY NOT bridged: recon stores only audit RESULT (recon.data.dependencies), not raw scripts/html the parser re-audits, and dependency findings already in FindingsStore via vuln phase — bridging = persist raw HTML in report.json (scope creep) for redundant run. User chose: header+cookie now, dependency deferred. Registry now: source_map_finder/safe_active_prober/header_audit/cookie_audit (additive). Commit 93f0fb5f. Tests in test_tool_evidence.py (shapes, empty/unfetched->{}, round-trip via parse_tool_output, available_tools). Verified report shapes: recon.data has server_headers/security_headers/technologies/dependencies/cms (NOT raw scripts/html); cookies.data.cookies. Remaining gaps: i18n, e2e/GUI tests, pagination of remaining tables.

*Confidence: 1 | Status: active | Created: 2026-06-30T19:32:51*

### Added e2e/GUI click-driven tests in try1 (gap clos...

Added e2e/GUI click-driven tests in try1 (gap closed). Harness in tests/gui_test_helpers.py: _SyncRunMixin overrides _run_async(work,on_done) to run inline (TaskRunnerMixin contract, synchronous, no QThread, deterministic) + reusable e2e hosts FindingsE2EHost(_SyncRunMixin,FindingsHost)/MissionsE2EHost(_SyncRunMixin,MissionsHost). tests/test_gui_e2e.py: genuine activations via QAbstractButton.click() (respects enabled-state, fires connected slot) over conftest-isolated stores — Findings select-row then assign/comment/status by click (assert store) + disabled-without-selection wiring; Missions run-tool by click (header_audit->finding ingested) + «Из скана» fill-evidence by click (monkeypatch core.config.load_settings output_dir to tmp, seed project scan with subdomains -> field auto-filled). Decision (user): synchronous _run_async; .click() activations (robust headless); representative scope (Findings+Missions), other tabs follow on same harness. Commit 3eb18aa6. Existing hosts/tests untouched. Pattern for future GUI e2e: subclass host with _SyncRunMixin + .click(). Remaining gaps: i18n, pagination of remaining tables.

*Confidence: 1 | Status: active | Created: 2026-06-30T21:34:44*

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

### Created full current-state review report for Advan...

Created full current-state review report for Advanced Site Analyzer at C:\Users\321\Documents\try1\ADVANCED_SITE_ANALYZER_FULL_REPORT_2026-07-02.txt. Report covers capabilities, maturity, architecture, GUI/Web/CLI surfaces, verification status, risks, and prompts for external AI review.

*Confidence: 1 | Status: active | Created: 2026-07-02T15:19:25 | Tags: `report`, `review`, `artifact`, `advanced-site-analyzer`*

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
