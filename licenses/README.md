# Bundled license texts — Advanced Site Analyzer (public build)

This directory holds the full license texts for the third-party components that
ship in the **default public build** (see `../THIRD_PARTY_NOTICES.md` for the
component/version inventory). It is bundled into the distributed `.exe`
(`build.spec` copies `licenses/` and `THIRD_PARTY_NOTICES.md` into the package).

The default build is **GPL-free**: PySide6-Fluent-Widgets (GPL-3.0) is **not**
bundled (`gui/_fluent.py` soft-degrades). Only the components below ship.

| Shipped component | Version | License | Text file |
|---|---|---|---|
| PySide6-Essentials / shiboken6 (+ bundled Qt 6 libraries) | 6.11.x | **LGPL-3.0** (used under the LGPL of its LGPL/GPL2/GPL3 tri-license) | `LGPL-3.0.txt` (+ `GPL-3.0.txt`, which the LGPL incorporates by reference) |
| qtpy | 2.4.x | MIT | `qtpy-LICENSE-MIT.txt` |
| requests | 2.34.x | Apache-2.0 | `Apache-2.0.txt` + `requests-NOTICE.txt` |
| beautifulsoup4 | 4.15.x | MIT | `beautifulsoup4-LICENSE-MIT.txt` |
| lxml | 6.1.x | BSD-3-Clause | `lxml-LICENSE-BSD-3-Clause.txt` |

Notes:

- **PySide6 / Qt (LGPL-3.0).** The PySide6 wheels ship only a commercial-license
  reference, so the canonical LGPL-3.0 and GPL-3.0 texts here were taken verbatim
  from other installed packages that carry them (fpdf2 for LGPL-3.0, ansible-core
  for GPL-3.0) — they are the standard, unmodified FSF documents. LGPL-3.0 also
  requires that the user be able to relink/replace the Qt libraries; the
  PyInstaller one-dir layout keeps them as replaceable shared libraries.
- **Apache-2.0 (requests).** The Apache license requires preserving the upstream
  `NOTICE` — included as `requests-NOTICE.txt`.
- **MIT / BSD.** Each file is the upstream package's own text (it carries the
  package's copyright line), copied verbatim from its installed distribution.

Optional dependencies (playwright, fastapi, uvicorn, fpdf2, scrapy) are **not**
bundled in the default build; if an operator installs them, their licenses apply
from their own distributions. Re-verify all of the above against the exact
versions in any release build before shipping.
