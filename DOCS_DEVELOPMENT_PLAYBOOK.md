# DOCS — Development Playbook

> **Single source of truth for step-by-step progress tracking.**
> Roadmap: **Authorized Enterprise Recon & Client-Safe Scaling**.
> This file is an architectural anchor. Update the status marker on every stage
> as work lands. Do **not** delete history — mark stages `[DONE]` in place.

---

## 0. Non-negotiable guardrails (apply to every epic)

This platform is strictly an **authorized-only** Asset Surface Management (ASM),
Continuous Security Monitoring (CSM), and **Client-Safe Pentest Workbench**. The
following are **STRICTLY FORBIDDEN** in any epic below:

- ❌ No stealth / evasion / unauthorized offensive features.
- ❌ No proxy-rotation engines designed to bypass blocks.
- ❌ No TOR / SOCKS5 anonymous tunneling mechanisms.
- ❌ No JA3/JA4 TLS fingerprint spoofing or user-agent deception engines.
- ❌ No un-throttled brute-forcing, automatic exploitation, or persistence payloads.

Instead, every increment optimizes for **enterprise-grade visibility**: maximize
**passive** reconnaissance, accurately calculate and report **scan coverage
gaps**, honor **Rules of Engagement (ROE)** budget limits, secure **local
multi-tenant** data storage, and enforce **strict input sanitization** against
malformed inputs.

Engineering invariants carried from `CLAUDE.md`:
- Offline-first: no network in core logic or tests; heavy deps stay optional and
  degrade softly. No new third-party dependencies without explicit need.
- UI stays thin; all logic lives in `core/` / `utils/`.
- Single sources of truth (`core/config.py`, `core/paths.py`,
  `core/project.py`, `core/secret_scanner.py`, `utils/endpoint_index.py`).
- Backward compatibility of layouts/contracts (`Projects/<domain>/`,
  `metadata.json`, `report.json`, audit-run JSON) must not break.

---

## 1. Roadmap schema (10 sequential epics)

| Epic | Name | Summary | Status |
|---|---|---|---|
| **E1** | Passive OSINT Intelligence Layer | Shodan, Censys, Cert Logs integrations with **zero target traffic**. | `[IN PROGRESS]` |
| **E2** | Coverage Gate & Capability Awareness | Explicit tracking of what was skipped/failed and **why**. | `[DONE]` |
| **E3** | Authorized Network Execution Profiles | Allowlist IPs, declared source nodes, legal refs. | `[DONE]` (contract) |
| **E4** | Browser-Backed Accuracy Mode | Playwright for **dynamic asset parsing**, not bypass. | `[DONE]` (accuracy layer) |
| **E5** | Context-Aware Wordlist Manager | Technology-targeted **safe** dictionary fuzzing within ROE budget. | `[DONE]` (planner) |
| **E6** | Origin Exposure & Cloud Edge Intelligence | **Passive** calculation of direct IP leaks behind CDNs. | `[DONE]` |
| **E7** | PostgreSQL Readiness / Storage Abstraction | Prepare local DB schema layer for enterprise scaling. | `[DONE]` (backend seam) |
| **E8** | Authorized Worker Orchestration | Central job queue and explicit node execution framework. | `[DONE]` (contract + store/dispatcher) |
| **E9** | Sensitive Data Governance | Redact raw secrets/credentials from client-facing reports. | `[DONE]` |
| **E10** | Parser Hardening & Input Limits | Guard core parsers against JSON bombs and huge-file DoS. | `[DONE]` |

---

## 2. Stage log (chronological)

### Stage 1 — E2: Coverage Gate Foundation — `[DONE]`

**Goal:** an offline-first core layer that normalizes *what ran, what was
skipped/failed, and why*, and surfaces it as a "Limitations & Coverage" section
in client-facing reports.

**Delivered:**
- `core/coverage.py` — pure/offline coverage model:
  - Status literals: `full`, `partial`, `skipped`, `failed`, `unavailable`.
  - Reason codes: `missing_dependency`, `scope_denied`, `roe_denied`,
    `failed_phase`, `skipped_phase`, `timeout`, `quota`, `auth_required`,
    `passive_only`.
  - `coverage_item(phase, status, reason=None, detail="")` — validated item.
  - `build_coverage_summary(items)` — totals, per-status counts, coverage
    ratio, overall project coverage status.
  - `coverage_from_audit_run(run)` — backward-compatible adapter that derives
    coverage from legacy/modern audit-run dicts without crashing.
  - `coverage_for_dependency(phase, feature, *, available=None, detail="")` —
    degrades a phase to `unavailable/missing_dependency` when an optional
    capability (e.g. Playwright, external binaries) is absent; detection is
    injectable for offline tests and otherwise reuses `core/features.py`.
  - `render_coverage_markdown(summary)` — escaped "Limitations & Coverage"
    Markdown section.
- `core/audit_report.py` — Markdown and HTML report outputs now append the
  "Limitations & Coverage" section, derived via a safe fallback when the run
  carries no explicit coverage data. The `render_json` data contract is left
  byte-compatible on purpose (JSON is the raw run payload, not a rendered
  report).
- `tests/test_coverage.py` — full coverage calc, dynamic degradation with a
  missing dependency, legacy-dict edge cases, Markdown escaping; plus report
  integration assertions.

**Backward-compatibility notes:** no schema change (the audit-run JSON schema
has no `additionalProperties: false`, and coverage is *derived*, not stored);
existing `audit_report` section-splitting tests remain valid because the new
section is appended after the Review Appendix; `render_json` output is
unchanged.

**Verification:** `ruff check core/coverage.py core/audit_report.py` clean;
`pytest tests/test_coverage.py` green.

---

### Stage 2 — E10: Parser Hardening & Input Limits — `[DONE]`

**Goal:** stand a DoS-resistance layer between the app's core parsers and
untrusted/oversized input (corrupt/tampered `report.json`, shared `.zip`
project bundles), with explicit, configurable limits.

**Delivered:**
- `core/safe_parse.py` — offline, stdlib-only guards:
  - Named configurable defaults: `MAX_JSON_BYTES` (64 MiB), `MAX_JSON_DEPTH`
    (200), `MAX_JSON_ITEMS` (10M), `MAX_MEMBER_BYTES` (64 MiB). Every entry
    point takes explicit overrides (configurable without a config-schema change).
  - `ParseLimitError(ValueError)` — subclassing `ValueError` keeps existing
    degrade-not-raise handlers working unchanged.
  - `json_nesting_depth` — linear, recursion-free, string-aware depth scan
    (strips string literals in C first, so brackets inside strings never count)
    → rejects JSON bombs **before** `json.loads` builds the graph.
  - `count_elements` — iterative (explicit stack) element budget; measures even
    interpreter-recursion-exceeding structures without `RecursionError`.
  - `safe_json_loads` / `safe_read_bytes` / `safe_read_text` / `safe_read_json`
    — byte-size + depth + element limits over strings, bytes, and files.
  - `safe_zip_read` / `safe_zip_json` / `member_within_limit` — decompression
    (zip) bomb guard on a member's *declared* uncompressed size before reading.
- Wired into the untrusted-input seams (behavior preserved for legitimate data):
  - `core/project.py::load_scan_report` → `safe_read_json`; oversized/bomb
    `report.json` now degrades to the existing `None` path.
  - `core/project_io.py` import → manifest and all DB-slice JSON members read via
    `safe_zip_json`; `_safe_extract` rejects an over-limit member up front
    (`member_within_limit`), complementing the existing zip-slip guard.
- `core/iac_scanner.py` already had its own `_MAX_FILE_BYTES` guard — left
  untouched (no need to churn working code).
- `tests/test_safe_parse.py` — depth scan (incl. brackets-in-strings), JSON-bomb
  rejection, iterative element counting on deep input, size limits, file
  readers, and the zip decompression-bomb guard.

**Backward-compatibility notes:** no schema/contract change; limits are
generous defaults with per-call overrides; the export path (`json.dumps`) is
untouched; `project_io` round-trip and `load_scan_report` callers behave
identically for legitimate inputs.

**Verification:** `ruff check core/safe_parse.py core/project.py
core/project_io.py` clean; targeted + full offline suite green.

---

### Stage 12 — E4: Browser-Backed Accuracy Mode — `[DONE]` (accuracy layer)

**Goal:** use a headless render to parse the assets a single-page app only
materializes after its JS runs, and *measure* the gap against static parsing —
an accuracy aid, never an evasion/bypass tool.

**Delivered:**
- `core/browser_accuracy.py`:
  - **Pure** DOM extraction — `extract_dom_assets(html, base_url)` parses the
    rendered DOM (stdlib `html.parser`, no new dependency) for links (split
    internal vs external by apex), form targets and subresource hosts; resolves
    against the base URL, deduped/sorted, malformed-safe.
  - **Pure** `accuracy_delta(static, rendered)` → per-category `added` lists +
    a summary (static/rendered totals, added count, `gain_pct`) — a concrete
    measure of what a static-only scan would have missed.
    `build_browser_accuracy(static_html, rendered_html, base_url)` combines them.
  - **Injectable, feature-gated render seam** — `capture_rendered_html(url,
    render_fn=None)`: a test injects `render_fn`; in production it renders via
    Playwright *only when installed* (`features.has_playwright`) and otherwise
    returns `status='unavailable'` (soft degrade); never raises. `_playwright_render`
    is a minimal goto + `page.content()` (network interception stays in
    `dynamic_analyzer`).
- `tests/test_browser_accuracy.py` — extraction/classification, dedup, scheme
  filtering, malformed-safe, delta (rendered-only assets + gain), the injected
  render path (success / error / unavailable) and an end-to-end offline run.

**Why complementary, not duplicate:** `core.dynamic_analyzer` intercepts network
traffic + probes runtime globals; it does not read the rendered DOM's asset
graph (anchor links / forms / subresource hosts), which is what accuracy mode
adds. No spoofing / anti-detection — a faithful render of an in-scope page only.

**Deferred (increment 2):** an opt-in collection phase that renders the target
and folds the accuracy delta into the report / E2 coverage (heavy + Playwright-
dependent, so kept out of this offline-tested core).

---

### Stage 13 — E8 increment 2: JobStore / NodeStore + dispatcher — `[DONE]`

**Goal:** persist the orchestration contract and run a claimed job via its
kind's runner.

**Delivered:**
- `core/job_store.py` — `JobStore` (the queue) + `NodeStore` (the explicit-node
  registry), each a single-table `SQLiteStore` mirroring `MissionStore`;
  **schema-validates the canonical payload before every write**
  (`asa_job` / `asa_worker_node`). Jobs: `save_job` (idempotent, preserves
  `created_at`), `get_job`, `list_jobs(project/status, priority-ordered)`,
  `delete_job`, and `claim_next_job(node)` — runs the pure scheduler over the
  pending **payloads** (not store rows) then persists the authorization-gated
  claim. Nodes: `save_node` / `get_node` / `list_nodes(authorized)` /
  `delete_node`.
- `core/job_dispatcher.py` — `run_job(job, runners, store=…)` moves a *claimed*
  job running→completed|failed via the **injected** runner map (real runners
  bound later via thin adapters), persisting each step; a missing runner or a
  runner exception is recorded as `failed` (transient `_error`) rather than
  raised, so a dispatch loop keeps draining. `dispatch_next(node, runners,
  store)` = claim + run. Accepts a pure job or a store row (`_pure`).
- `tests/test_job_store.py` — store CRUD + idempotence + ordering + claim
  persistence + incapable-node refusal; node CRUD; dispatcher complete /
  no-runner / runner-error / non-claimed-raises / dispatch_next drain.

**Note (bug caught in review):** the first cut passed store **rows** (job nested
under `payload`) to the pure scheduler, which mis-normalized them (fresh ids /
empty targets) and left the original row pending. Fixed by extracting the pure
payloads before scheduling — verified by the drain test.

**Backward-compatibility:** touches **no existing file** — two new stores + a
dispatcher + the E8 schemas already present. Not wired into `project_io` bundles
(operational infra, not project artifacts). No hot-path change.

**Deferred:** binding the real runners (collection/audit/mission/tool/retest) and
a GUI/web/CLI surface for the queue.

---

### Stage 11 — E8: Authorized Worker Orchestration — `[DONE]` (contract)

**Goal:** the model for a central job queue + explicit worker-node framework —
so authorized scan/audit work can be scheduled across declared nodes.

**Delivered:**
- `core/orchestration.py` — pure/offline contract (holds no state, no threads,
  no sockets, executes nothing):
  - **Jobs**: `create/normalize/validate/advance_job_status/assign_job/job_to_json`
    over the platform's existing client-safe run kinds (`full_collection`,
    `audit_run`, `mission_run`, `tool_run`, `retest_run`). Lifecycle
    pending→claimed→running→completed|failed (+cancel / release).
  - **Nodes**: `register_node/normalize_node/node_can_run/node_to_json` — a node
    is **inert until `authorized=True`**, must be `active`, and must **declare
    the capability** for a kind.
  - **Scheduler**: `assign_job` is authorization-gated (`node_can_run`);
    `claim_next(jobs, node)` deterministically picks the best pending job the
    node may run (priority, then age, then id). Pure — it selects; it never
    mutates the queue or runs the job.
- `schemas/asa_job.schema.json` + `asa_worker_node.schema.json` + `audit_schema`
  aliases; `job_to_json` / `node_to_json` are schema-valid.
- `tests/test_orchestration.py` — node authorization gate, job lifecycle +
  illegal transitions, assignment refusals (unauthorized / incapable /
  non-pending), scheduler ranking + filtering, schema conformance.

**Authorization guardrails (in the contract):** no covert/auto node — a node
must be registered *and* authorized *and* capability-declared before any job can
reach it; job kinds are the existing client-safe run types only. Purely
additive — new module + schemas + 2-line alias; no hot-path change.

**Deferred:** a persistent JobStore/NodeStore and a real dispatcher (execute a
claimed job via the mapped runner, heartbeat nodes) build on this contract next.

---

### Stage 10 — E5: Context-Aware Wordlist Manager — `[DONE]` (planner)

**Goal:** turn detected technologies + the ROE budget into a *small, targeted,
bounded* list of paths worth checking — never a blind mega-dictionary brute
force.

**Delivered:**
- `core/wordlist_manager.py` — pure/offline **planner** (selects + caps
  candidates; never sends a request):
  - Curated, precision-first path dictionaries by category (baseline
    generic/config/vcs + api + per-tech wordpress/php/django/laravel/spring/
    nodejs/tomcat). `categories_for` / `select_paths` map detected technologies →
    relevant paths (deterministic, deduped); `technologies_from_report` reads the
    recon fingerprint.
  - `budget_from_roe` derives a request cap from the ROE `rate_limit` via the
    SSOT `host_throttle.rate_per_sec` (rate × window, floored at 1, hard-capped
    at 500; conservative default 50 when no rate declared).
  - `plan_wordlist(technologies, roe, …)` → `{authorized, reason, candidates,
    total_available, budget, truncated, categories}`. **Refuses to plan
    (authorized=False, empty candidates) when the ROE is passive-only /
    active-disabled** — path probing is an active action — and otherwise caps
    the list to the smaller of the ROE budget and any explicit `max_candidates`.
- `tests/test_wordlist_manager.py` — category/path selection, dedup/determinism,
  budget math + cap, and the ROE gate (active authorizes, passive refuses,
  truncation, explicit max, default-passive ROE).

**Guardrails:** it plans, never probes; no brute force (`action_policy` forbids
it); it stays within the authorized request budget and honors passive-only ROE.
Purely additive — a new module + test, nothing else touched, no new dependency.

**Deferred:** an opt-in active probe phase that *executes* a plan (scope-gated,
throttled via the existing per-host throttle) is a future increment; the plan is
the safe half.

---

### Stage 9 — E7: Storage Abstraction / PostgreSQL readiness — `[DONE]` (backend seam)

**Goal:** stop the stores from hard-coding `sqlite3` — introduce the seam a
future PostgreSQL backend plugs into — with byte-identical current behaviour.

**Delivered:**
- `utils/db_backend.py` — `DatabaseBackend` interface (owns *connection creation
  + per-connection dialect setup*; exposes `dialect` / `placeholder` /
  `supports_pragmas` for future dialect-aware SQL) and `SQLiteBackend` (reproduces
  the old `sqlite3.connect` + `Row` factory + durability PRAGMAs exactly).
  `resolve_backend(dsn)` factory: bare path / `sqlite://…` / `:memory:` →
  `SQLiteBackend`; `postgres://` / `postgresql://` → a documented
  `NotImplementedError` (the wiring point for later); empty → `ValueError`.
- `utils/sqlite_store.py` — `SQLiteStore.__init__(db_path, *, backend=None)` now
  builds (or accepts an injected) backend; `_connect` gets the connection from
  `backend.connect()` **outside** the try (connect-time corruption raises as
  before) and calls `backend.prepare()` (row factory + PRAGMAs) **inside** the
  try (leak-safe). `_apply_pragmas` is preserved as a public delegator to the
  backend. No store subclass changed — they all inherit the seam.
- `tests/test_db_backend.py` — backend connect/prepare/WAL, DSN resolution
  (path / scheme / memory / postgres-seam / empty), and `SQLiteStore` routing
  through the default and an injected backend.

**Backward-compatibility notes:** the transaction lifecycle
(commit/rollback/close) and the exact connect-outside-try / prepare-inside-try
ordering are unchanged; every store keeps working through the default
`SQLiteBackend`; `backend=` is keyword-only, so all `super().__init__(db_path)`
calls are unaffected. `core/backup.py`'s SQLite online-backup is a separate
concern, intentionally left as-is.

**Deferred:** the remaining dialect ops a Postgres backend needs (parameter
placeholder in generated SQL, `user_version`→a metadata table, `PRAGMA
table_info`→`information_schema`, `INSERT OR REPLACE`→`ON CONFLICT`) are the
next increment; the seam and metadata for them now exist.

---

### Stage 8 — E3: Authorized Network Execution Profiles — `[DONE]` (contract)

**Goal:** declare the network boundaries and legal basis of an authorized run —
the IP dimension the domain/action ROE lacks.

**Delivered:**
- `core/execution_profile.py` — pure/offline contract (mirrors the
  `pentest_mission` / `engagement` idiom): `create` / `normalize` / `validate` /
  `ip_authorized` / `profile_expired` / `summary` / `to_json`. Fields:
  `allowed_ips` / `denied_ips` (validated IP/CIDR via stdlib `ipaddress`;
  host-bits normalized, invalid dropped), `source_nodes` (declared testing
  origins for client allowlisting / auditability), and `legal`
  (authorized_by / reference / contract_id / valid_from / valid_until / notes).
  - **Default-deny:** an empty allowlist authorizes nothing; an explicit
    `denied_ips` match wins over the allowlist; a malformed target IP is denied.
  - `validate_execution_profile` gates a profile as *binding* (non-empty
    allowlist + legal authorized_by/reference; malformed IP/CIDR flagged).
- `schemas/asa_execution_profile.schema.json` + `audit_schema` alias
  (`asa_execution_profile`) — `to_json` output is schema-valid.
- `tests/test_execution_profile.py` — normalize/CIDR, validation gates,
  default-deny `ip_authorized` (allow / deny-wins / outside / empty / malformed /
  single-host), expiry window, summary, schema conformance.

**Why complementary, not duplicate:** the engagement schema records
`scope.allowed_ips` as bare strings but nothing validates them as CIDR, enforces
membership, declares source nodes, or checks a validity window — this is the
operational network-authorization layer that answers "is this target IP
authorized right now?".

**Deferred (increment 2):** a store + scan-time enforcement seam (consult the
active profile's `ip_authorized` before touching a resolved target IP) and GUI/
config surfaces — kept out of this contract-first increment.

---

### Stage 7 — E6: Origin Exposure & Cloud Edge Intelligence — `[DONE]`

**Goal:** passively flag a potential **CDN bypass** — when the apex is behind a
pure CDN edge (Cloudflare/Fastly/Akamai) but names in the same footprint resolve
to non-CDN IPs, those are candidate origin servers reachable directly.

**Delivered:**
- `core/origin_exposure.py` — pure/offline/derive-on-read over the scan report,
  reusing `cloud_classifier` (SSOT) for edge-vs-origin classification:
  `build_origin_exposure(report)` → `{behind_cdn, edge:{cloud,ip},
  candidates:[{ip,host,source,cloud}], exposed, summary}`. `exposed` is True only
  when the apex is behind a CDN edge **and** a non-CDN candidate exists. Skips
  the apex edge IP and CDN-fronted subdomains; deduped by IP; never raises.
- `core/collection_runner.py` — `_build_origin_exposure(report)` (best-effort,
  after technology-risk) attaches `report['origin_exposure']`; HTML report gains
  an "Origin Exposure (CDN bypass)" card. **Display/intel only — the risk verdict
  is untouched** (like exposure/criticality).
- `core/report_export.py` — `report_markdown` adds an "Origin Exposure" section
  when exposed.
- `tests/test_origin_exposure.py` — exposure detection, edge-IP / CDN-fronted
  exclusions, dedup, derived edge cloud, malformed-input safety, and the
  collection_runner / markdown / HTML surfaces.

**Backward-compatibility notes:** purely additive and derive-on-read — no new
scanner, no target traffic, no new dependency; consumes recon + the opt-in
subdomain phase already in the report; the authoritative risk score is
unchanged; candidates are framed as *leads to verify*, never asserted as the
origin (client-safe, false-positive-averse).

**Data source note:** increment 1 uses the subdomain phase's resolved A-records.
Future sources (asn_intel reverse-IP co-hosts, cert-SAN / DNS history, running
InternetDB on candidate IPs) can extend `_origin_candidates` additively.

---

### Stage 6 — E1: Passive OSINT opt-in scan-path wiring — `[DONE]` (increment 2)

**Goal:** wire the keyless InternetDB provider into Full Collection as an opt-in
phase that enriches the asset inventory and shows in the Coverage Gate — zero
target traffic, off by default.

**Delivered:**
- `core/collection_runner.py`:
  - Opt-in `passive_osint` flag (ctor + `configure`), resolved via
    `_passive_osint_enabled()` which also honours the `passive_osint.enabled`
    setting (so it can be turned on without a GUI toggle; mirrors
    `_scan_concurrency`'s settings read).
  - `_phase_passive_osint(report)` — looks the recon-resolved IP(s) up via
    `passive_osint.query_internetdb` (zero target traffic), rolls up
    ports/hostnames/CPEs/CVEs; soft-degrades to `Skipped` (no IP / no data) and
    backstops any unexpected error to `Error` — never sinks a scan.
  - `_osint_target_ips(report)` — recon IP + infra-chain IP, validated/deduped.
  - Added to the concurrent DAG (deps `recon`, **not** scope-gated — it queries
    Shodan's dataset, like the threat feed) and to `_PHASE_ORDER`, so a
    concurrent run stays byte-identical. HTML report gains a Passive OSINT card;
    the phase automatically appears in the E2 Coverage Gate.
- `core/asset_adapter.py` — `derive_assets` folds the `passive_osint` phase's
  hosts/IPs/CPEs into the inventory with `source='passive_osint'` (added last, so
  first-wins dedup never disrupts native assets; correct per-phase GONE-gating).
- `core/passive_osint.py` — `osint_to_assets` gains a `source` override.
- `core/config.py` — `passive_osint: {enabled: False}` (off by default; keyless,
  zero target traffic; CVEs are intel-only, not promoted to findings).
- `tests/test_passive_osint_scan.py` — gating, IP resolution, phase
  success/skip/error backstop, asset fold, HTML card, coverage appearance.

**Backward-compatibility notes:** off by default (flag + setting), so existing
scans are unchanged; `sync` only upserts the new assets (GONE-gating keys on the
new `passive_osint` source, so no existing asset can flap); CVE associations stay
out of the authoritative findings store (client-safe — they are unverified CPE
inferences). The sequential↔concurrent equality test still passes.

**Design decision (locked):** CVEs from passive OSINT are *intel only*
(shown in the report/card, counted in coverage) and are **not** promoted to
`FindingsStore`, to avoid unverified CPE→CVE associations inflating a
client-facing risk verdict. `osint_to_findings` remains available for a future
keyed-provider increment where a confirmed source justifies promotion.

**Verification:** `ruff` clean; passive OSINT + asset + collection_runner (incl.
seq↔concurrent equality) + full offline suite green.

---

### Stage 5 — E1: Passive OSINT layer — provider contract + first keyless source — `[DONE]` (increment 1)

**Goal:** start E1 with a keyless, **zero-target-traffic** passive OSINT layer,
contract-first and fully offline-testable, before any scan-path wiring.

**Delivered:**
- `core/passive_osint.py` — pure/offline, mirrors the `update_check` /
  `threat_feed` seam pattern (injectable `_fetch`, HTTPS-only, never raises):
  - `PassiveSource` registry (`PASSIVE_SOURCES`) + `list_sources` — keyless-first;
    keyed providers (Shodan API, Censys) plug in here later behind an opt-in key.
  - First provider **Shodan InternetDB** (`internetdb.shodan.io/{ip}`): reads
    Shodan's dataset by IP, so our process sends **no packet to the target** —
    the canonical E1 "zero target traffic" source, keyless. `query_internetdb`
    validates the IP locally (no request for a non-IP), `parse_internetdb`
    normalizes ports/hostnames/cpes/tags/vulns.
  - `osint_to_assets` / `osint_to_findings` — map into the canonical
    `asset_adapter.Asset` / `findings_adapter.from_raw` DTOs (CVEs get canonical
    identity so they dedup with scanner findings; emitted at `Info` +
    "passive/unverified" detail). **No store writes, no risk-score impact.**
- `tests/test_passive_osint.py` — registry, parse normalization/edge cases,
  injected-transport query (non-IP short-circuits, soft-degrade on error,
  IPv6), HTTPS-only guard, and DTO mapping.

**Backward-compatibility notes:** purely additive — a new module + test, no
existing file touched, no new dependency (stdlib `urllib`/`ipaddress`/`json`).
Nothing runs unless a caller invokes it.

**Next E1 increments (deferred):** opt-in scan-path wiring (enrich synced IP
assets via InternetDB, gated by a setting, feeding `_sync_assets`/coverage), then
keyed providers (Shodan API / Censys) behind configured keys, then a cert-log
provider consolidating existing CT usage.

---

### Stage 4 — E2: Coverage Gate wired to live scan phase statuses — `[DONE]`

**Goal:** turn the E2 coverage summary from a derived report-time fallback into
**real per-scan coverage** sourced from Full Collection's live phase outcomes,
and surface it in the scan deliverables.

**Delivered:**
- `core/coverage.py` — new `coverage_from_scan_report(report)` adapter: maps
  each `report['phases'][name]` outcome (`Success`→`full`, `Error`→`failed`/
  `failed_phase`, `Skipped`→`skipped` with the reason classified as
  `scope_denied` / `missing_dependency` / `skipped_phase`) into a coverage
  summary. Never raises on malformed input; details are truncated.
- `core/collection_runner.py` — `_build_coverage(report)` (best-effort, mirrors
  `_build_osint_catalog`) attaches `report['coverage']` right after the OSINT
  catalog / before the executive summary; the risk verdict is untouched. The
  HTML report gains a "Limitations & Coverage" card (reuses
  `coverage.render_coverage_html`).
- `core/report_export.py` — `report_markdown` appends the "Limitations &
  Coverage" section from `report['coverage']` (or derives it from phases, so
  older reports still surface it).
- `tests/test_coverage.py` — scan-adapter mapping (all outcomes + reason
  classification), detail truncation, malformed-input safety, and the
  `report_markdown` integration (section appended when phases exist, absent
  otherwise).

**Backward-compatibility notes:** `report['coverage']` is additive to the free
`report.json`; no schema/contract change. Coverage build is best-effort and
never fails a scan. Reports without phases render exactly as before.

**Verification:** `ruff check` clean; coverage + report_export +
collection_runner (incl. the sequential↔concurrent equality test) + full
offline suite green.

---

### Stage 3 — E9: Sensitive Data Governance — `[DONE]`

**Goal:** guarantee no raw secret/credential value reaches a client-facing
report, even if an upstream field held plaintext — defense-in-depth at the
report boundary (findings are already masked at capture/store time).

**Delivered:**
- `core/data_governance.py` — pure/offline render-time redaction, reusing the
  single sources of truth (no second detector/masker):
  - detection = `core.secret_scanner.RULES`; masking =
    `core.finding_fingerprint.mask_value` (`prefix…len` — keeps vendor/type
    context, drops the secret body).
  - `redact_text` — mask any embedded secret in a string (group-aware, so
    `Bearer <tok>` / `api_key="<v>"` keep their label); idempotent; non-strings
    pass through.
  - `is_sensitive_key` / `redact_data` — recursive structure redaction: a
    string under a sensitive key (password/token/secret/authorization/cookie/
    `match`/…) is masked wholesale; non-string values (ints/bools) are never
    masked, so false friends (`match_count`, `auth_context`) are safe. Input is
    never mutated.
  - `redact_finding` / `govern_rows` — governed copies of finding rows.
- Wired at the client-facing finding-table choke points (a no-op on clean rows,
  so existing report output is byte-identical):
  - `core/finding_render.py` `finding_md_table` / `finding_html_table` (covers
    mission + engagement reports).
  - `core/audit_report.py` `_md_table` + the inline HTML `table()`.
- `tests/test_data_governance.py` — vendor-key/JWT/Bearer/contextual masking,
  idempotence, sensitive-key rules, non-mutation, and report-boundary
  integration (a planted raw secret never appears in the rendered Markdown/HTML;
  clean reports unchanged).

**Backward-compatibility notes:** governance only rewrites string content that
matches a secret rule or sits under a sensitive key, so normal findings render
identically; no schema/contract/stored-evidence change; masking style matches
the existing `mask_value` convention used elsewhere in reports.

**Verification:** `ruff check core/data_governance.py core/finding_render.py
core/audit_report.py` clean; governance + all report suites + full offline
suite green.

---

## 3. Next up

**Every one of the 10 roadmap epics (E1–E10) now has a landed, tested
increment.** Foundational passes done: E2/E6/E9/E10 fully wired; E1 (passive
OSINT: contract + opt-in scan phase); E3/E5/E7/E8/E4 (contract / planner / seam /
accuracy layer).

**Remaining work is depth (increment 2s), all offline and self-contained:**
- E1-3 — keyed passive providers (Shodan API / Censys) behind a configured key.
- E3-2 — scan-time `ip_authorized` enforcement seam (refuse an unauthorized
  target IP).
- E4-2 — opt-in render phase folding the accuracy delta into report / coverage.
- E5-2 — opt-in scope-gated, throttled probe phase that executes a plan.
- E7-2 — Postgres dialect ops (placeholder / `user_version` / `table_info` /
  upsert) + a real `PostgresBackend`.
- E8-2 — `JobStore`/`NodeStore` + a dispatcher that runs a claimed job via its
  mapped runner.

Pick any; each is a small, low-risk follow-up on an existing contract.
