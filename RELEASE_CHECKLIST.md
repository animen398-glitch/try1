# Release Checklist — Advanced Site Analyzer

Target version: **1.0.0** (`core/config.APP_VERSION`). Local-only workflow:
commits happen locally; publishing/signing/distribution is done by a human.

Legend: ✅ done · ◻ open · ⚠ needs a decision · ⏭ deferred (not a blocker).

---

## A. Verification checkpoint (repeat immediately before tagging)

- ✅ `ruff check` clean across the tree.
- ✅ Full offline `pytest` — exit 0 (headless, no network).
- ✅ GUI self-check — `python main.py --self-check` builds all **30** tabs.
- ◻ Frozen smoke — build with `pyinstaller build.spec --clean --noconfirm`,
  then run the frozen `--self-check` and confirm 30 tabs + no console windows
  (`console=False`). *Run on the packaging machine.*
- ✅ Test count synced to **2999** (254 files, exit 0) in `PROJECT_REPORT.md`,
  `PROJECT_STATUS.txt`, `CLAUDE.md` / `AGENTS.md` (re-confirm at the release commit).

## B. Licensing & legal hygiene

- ✅ Third-party dependency + license inventory — `THIRD_PARTY_NOTICES.md`
  (generated from installed metadata 2026-07-05).
- ✅ **PySide6-Fluent-Widgets (GPL-3.0) — resolved: OMITTED from the default
  build.** Decision (2026-07-05): public distribution, ship GPL-free. `build.spec`
  no longer bundles qfluentwidgets and excludes it from the graph by default;
  `gui/_fluent.py` soft-degrades to a text-only side-nav (native `QMainWindow`
  shell is unaffected). Internal builds holding a commercial license can still
  bundle it with `ASA_BUNDLE_FLUENT=1`.
- ⚠ **Project LICENSE undecided.** No top-level `LICENSE` file exists — pick the
  distribution license (proprietary vs. open). No longer GPL-constrained now that
  Fluent-Widgets is omitted; any license (incl. proprietary) is available.
- ✅ Full license texts bundled — `licenses/` holds the shipped components'
  texts (LGPL-3.0 + GPL-3.0 for PySide6/Qt, Apache-2.0 + NOTICE for requests,
  MIT for qtpy/beautifulsoup4, BSD-3-Clause for lxml), copied verbatim from the
  installed distributions; `build.spec` ships `licenses/` + `THIRD_PARTY_NOTICES.md`
  in the `.exe`. See `licenses/README.md`.

## C. Changelog & versioning

- ✅ `CHANGELOG.md` `[Unreleased]` reconciled with the whole post-1.0.0 body of
  work (workbench, missions, engagements, retest, tool layer, KEV/EPSS, risk
  acceptance, search, compare, enterprise recon, reliability, GPL-free build;
  media downloading under Removed).
- ⚠ Decide the release version + bump `APP_VERSION`, then move `[Unreleased]`
  under it with a date. Note: media downloading was **removed** since 1.0.0, so
  SemVer argues for a major bump — maintainer's call.

## D. Packaging & clean-machine acceptance

- ◻ Produce the `.exe` (`build.spec`), verify it launches on a clean Windows
  machine with no dev toolchain present.
- ◻ Confirm `ASA_DATA_ROOT` override works in the frozen build (data/config
  under one directory).
- ✅ Fluent-Widgets absence degrades gracefully — GUI builds all 30 tabs without
  qfluentwidgets (`tests/test_fluent_optional.py`, subprocess self-check).
- ◻ Confirm remaining optional deps degrade gracefully when absent (no Playwright/
  fastapi/scrapy → feature disabled with a hint, app still runs).
- ⏭ Installer + code signing (nice-to-have; done by a human at packaging time).

## E. End-to-end authorized demo (pilot)

- ✅ Ran the full operator flow on `demo_seed.py` data (2026-07-05):
  project → scan → assets/findings → triage (assign/comment/status) →
  **risk acceptance** (accept + expiry + expired-only filter) → attack path →
  remediation → mission run (offline audit run → completed) → engagement report
  → retest run (→ completed) → mission report → GUI read-chain (30 tabs). **11/11
  stages passed; no product defects surfaced.** (Only harness/env issues found:
  `load_scan_report` is a `Project` method, store rows key by `id` with the
  canonical dict under `payload`, and the GUI's `QT_API=pyside6` pin is required
  to avoid a cross-binding `RenderHints` enum mismatch — all correct app
  behaviour.)
- ✅ No defects to fix from this pilot. (Re-run the pilot on a **fresh** seed —
  it mutates the workspace, so a second run on the same data double-counts.)

---

## Decisions

1. ✅ **Release channel** — public distribution (strict compliance path).
2. ✅ **Fluent-Widgets / GPL** — omit from the default build (GPL-free); the app
   soft-degrades. `ASA_BUNDLE_FLUENT=1` re-enables it for licensed internal builds.
3. ⚠ **Project license** — still open: pick proprietary or an open license
   (unconstrained now). Needed before a public ship.
