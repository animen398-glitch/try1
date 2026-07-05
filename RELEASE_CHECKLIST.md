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
- ◻ Reconcile the exact test count in `PROJECT_REPORT.md` / `PROJECT_STATUS.txt`
  with the final run at the release commit.

## B. Licensing & legal hygiene

- ✅ Third-party dependency + license inventory — `THIRD_PARTY_NOTICES.md`
  (generated from installed metadata 2026-07-05).
- ⚠ **PySide6-Fluent-Widgets is GPL-3.0.** Choose per release channel: omit it
  (app soft-degrades to `QTabWidget`), buy the commercial license, or ship the
  whole build under a GPL-compatible license. See `THIRD_PARTY_NOTICES.md` §4.1.
- ⚠ **Project LICENSE undecided.** No top-level `LICENSE` file exists — pick the
  distribution license (proprietary vs. open); constrained by the GPL decision.
- ◻ Bundle full license texts (LGPL-3.0, GPL-3.0, Apache-2.0, MIT, BSD-3-Clause)
  in the distributed build, next to `THIRD_PARTY_NOTICES.md`.

## C. Changelog & versioning

- ◻ Reconcile `CHANGELOG.md` `[Unreleased]` with everything shipped since 1.0.0
  (findings search, acceptance arc, missions/engagements, retest runs, tool
  layer, Windows CLI hardening, enterprise recon, …) and move it under the
  release version + date.
- ◻ Confirm `APP_VERSION` matches the tag; bump if this is a new release.

## D. Packaging & clean-machine acceptance

- ◻ Produce the `.exe` (`build.spec`), verify it launches on a clean Windows
  machine with no dev toolchain present.
- ◻ Confirm `ASA_DATA_ROOT` override works in the frozen build (data/config
  under one directory).
- ◻ Confirm optional deps degrade gracefully when absent (no Playwright/fastapi/
  scrapy/Fluent-Widgets → feature disabled with a hint, app still runs).
- ⏭ Installer + code signing (nice-to-have; done by a human at packaging time).

## E. End-to-end authorized demo (pilot)

- ◻ Run the full operator flow on `demo_seed.py` data:
  project → scan → assets/findings → triage → **risk acceptance** → attack path
  → remediation → mission/engagement → report → retest.
- ◻ File and fix **only** defects surfaced by this pilot before adding anything
  new. No new scanners for count's sake.

---

## Open decisions for the maintainer

1. **Fluent-Widgets / GPL** — omit, license commercially, or GPL the build?
2. **Project license** — proprietary or open (which)?
3. **Release channel** — internal/authorized use vs. public distribution
   (changes how strict B/D must be).
