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
| **E3** | Authorized Network Execution Profiles | Allowlist IPs, declared source nodes, legal refs. | `[NOT STARTED]` |
| **E4** | Browser-Backed Accuracy Mode | Playwright for **dynamic asset parsing**, not bypass. | `[NOT STARTED]` |
| **E5** | Context-Aware Wordlist Manager | Technology-targeted **safe** dictionary fuzzing within ROE budget. | `[NOT STARTED]` |
| **E6** | Origin Exposure & Cloud Edge Intelligence | **Passive** calculation of direct IP leaks behind CDNs. | `[NOT STARTED]` |
| **E7** | PostgreSQL Readiness / Storage Abstraction | Prepare local DB schema layer for enterprise scaling. | `[NOT STARTED]` |
| **E8** | Authorized Worker Orchestration | Central job queue and explicit node execution framework. | `[NOT STARTED]` |
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

**Stage 6 → E1 increment 2 (opt-in scan-path wiring):** enrich the IP assets a
scan already discovers via Shodan InternetDB, behind an opt-in setting
(`passive_osint.enabled`, off by default), feeding `_sync_assets` and the E2
Coverage Gate as a new phase — soft-degrading, zero target traffic. Then E1
increment 3: keyed providers (Shodan API / Censys) behind configured keys. E3–E8
(network profiles, browser-accuracy, wordlists, origin-exposure, Postgres
readiness, worker orchestration) remain larger integration efforts afterward.
