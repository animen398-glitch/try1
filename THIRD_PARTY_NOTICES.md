# Third-Party Notices — Advanced Site Analyzer

Advanced Site Analyzer bundles and/or depends on the third-party components
listed below. Each remains under its own license; the copies distributed with
this product are unmodified unless noted. License names and versions were read
from the installed package metadata (`importlib.metadata`) on 2026-07-05 and
should be re-verified against the exact versions shipped in any release build.

> Purpose statement is unchanged: this product is for **authorized security
> testing, research, and education only.**

---

## 1. Runtime dependencies (required)

These are imported by the GUI / packaged `.exe`.

| Component | Version pinned | Installed | License | Notes |
|---|---|---|---|---|
| PySide6-Essentials | `>=6.7,<7.0` | 6.11.1 | LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only | Qt for Python. Used under **LGPL-3.0**. See §3 for LGPL obligations. |
| qtpy (QtPy) | `>=2.4,<3.0` | 2.4.3 | MIT | Binding-abstraction seam. |
| requests | `>=2.31.0,<3.0` | 2.34.2 | Apache-2.0 | HTTP client. |
| beautifulsoup4 | `>=4.12.0,<5.0` | 4.15.0 | MIT | HTML parsing. |
| lxml | `>=5.1.0,<7.0` | 6.1.1 | BSD-3-Clause | Fast HTML/XML parsing. |

## 2. Runtime dependencies (optional, soft-degrading)

The app runs without these; each feature disables itself with a hint when its
dependency is absent. **None are bundled into the `.exe`.**

| Component | Version pinned | Installed | License | Feature |
|---|---|---|---|---|
| PySide6-Fluent-Widgets | `>=1.7,<2.0` | 1.11.2 | **GPL-3.0** ⚠ | Fluent side-navigation. **See §4 — distribution gate.** Soft-degrades to a plain `QTabWidget` when absent. |
| playwright | `>=1.40.0,<2.0` | 1.60.0 | Apache-2.0 | Dynamic traffic analysis (also needs a browser download). |
| fastapi | `>=0.110.0,<1.0` | 0.136.3 | MIT | LAN web console. |
| uvicorn | `>=0.27.0,<1.0` | 0.49.0 | BSD-3-Clause | ASGI server for the web console. |
| fpdf2 | `>=2.7,<3.0` | 2.8.7 | LGPL-3.0-only | PDF export of the vulnerability report. |
| scrapy | `>=2.11,<3.0` | 2.16.0 | BSD-3-Clause | Deep-crawl plugin (runs in a child process). |

## 3. Development / test dependencies (not distributed)

Present only for building and testing; never shipped in a release artifact.

| Component | Version pinned | Installed | License |
|---|---|---|---|
| pytest | `>=8.0,<10.0` | 9.0.3 | MIT |
| ruff | `>=0.5,<1.0` | 0.15.16 | MIT |
| httpx | `>=0.27.0,<1.0` | 0.28.1 | BSD-3-Clause |
| PyInstaller | build-time | — | GPL-2.0-with-exception (output `.exe` is unrestricted) |

External security CLIs (nuclei, katana, amass, subfinder, httpx, bbot, …) are
**independent optional integrations** invoked as separate processes. They are
not bundled or linked; each carries its own license and must be obtained
separately by the operator.

---

## 4. Distribution gates — action required before shipping

1. **PySide6-Fluent-Widgets is GPL-3.0 — RESOLVED: omitted from the default
   build.** The public build ships GPL-free: `build.spec` does not bundle
   qfluentwidgets and excludes it from the graph, and `gui/_fluent.py`
   soft-degrades to a text-only side-navigation (the native `QMainWindow` shell
   is unaffected). Internal builds that hold the author's commercial license may
   re-enable bundling with `ASA_BUNDLE_FLUENT=1`; that variant must then comply
   with that license (and is **not** the GPL-free artifact described here).

2. **LGPL components (PySide6, fpdf2 if shipped).** LGPL-3.0 requires that the
   end user be able to relink/replace the LGPL library. For a PyInstaller
   one-file/one-dir build this generally means: keep the Qt libraries as
   replaceable shared objects (the default one-dir layout satisfies this better
   than a fully static one-file), and include this notice + the LGPL text.

3. **Project's own license is undecided.** The repository has no top-level
   `LICENSE` file. The distribution license (proprietary vs. open) must be
   chosen; if GPL components are bundled, that choice is constrained by §4.1.

Bundle the applicable full license texts (LGPL-3.0, GPL-3.0, Apache-2.0, MIT,
BSD-3-Clause) alongside this notice in any distributed build.
