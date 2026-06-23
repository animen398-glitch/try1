"""core/severity.py
Canonical severity vocabulary — the single source for the platform's severity
scale and its numeric rank.

Like ``core/security_headers.py``, this is a tiny SSOT module: the modules that
compare or gate on severity (ci_gate, compliance, github_issues, …) share one
ordering instead of each re-declaring the same dict and risking drift.
"""

from typing import Dict, Tuple

# Severity scale, worst first — the platform vocabulary.
SEVERITY_ORDER: Tuple[str, ...] = ('critical', 'high', 'medium', 'low', 'info')

# Numeric rank derived from the order: higher number = more severe
# (critical=4 … info=0). Used for min-severity thresholds and "worst of"
# comparisons.
RANK: Dict[str, int] = {sev: len(SEVERITY_ORDER) - 1 - i
                        for i, sev in enumerate(SEVERITY_ORDER)}
