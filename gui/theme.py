"""gui/theme.py — single source of truth for the application's visual theme (F6).

Variant A of the GUI redesign: a PyQt5 *restyle*, not a binding migration. The
whole app is themed at once via the Fusion style + a ``QPalette`` (plus a tiny
supplemental QSS for what the palette doesn't reach, e.g. tooltips), applied once
on the ``QApplication`` — so no per-tab stylesheet sweep is needed and there is
**no new runtime dependency** (pure PyQt5), keeping the ``.exe`` unchanged.

Opt-in: ``settings['gui_theme']`` defaults to ``'system'``, which leaves the
current look untouched (Fusion's standard palette). Only ``'dark'`` overrides the
palette, so nothing changes visually until the user chooses it. This module is
the single place chrome colours live — widgets pull from ``DARK`` rather than
hardcoding hex (see gui/ui_components.py).
"""

from qtpy.QtGui import QColor, QPalette

# Selectable themes. ``system`` and ``light`` both render as Fusion's standard
# (light) palette today; ``light`` is kept distinct so a dedicated light palette
# can diverge later without another settings migration.
THEMES = ('system', 'light', 'dark')
DEFAULT_THEME = 'system'

# Dark palette — the single source of chrome colours (Win11/Defender-ish dark).
DARK = {
    'window':        '#252526',
    'base':          '#1e1e1e',
    'alt_base':      '#2d2d30',
    'text':          '#d4d4d4',
    'disabled_text': '#6d6d6d',
    'button':        '#333337',
    'bright_text':   '#ff5252',
    'accent':        '#0078d4',
    'accent_text':   '#ffffff',
    'tooltip_bg':    '#2d2d30',
    'border':        '#3c3c3c',
    'link':          '#4fc3f7',
    'placeholder':   '#808080',
    'disabled_hl':   '#3a3a3a',
}


def dark_palette() -> QPalette:
    """A Fusion-friendly dark ``QPalette`` built from the ``DARK`` colours."""
    d = DARK
    p = QPalette()
    p.setColor(QPalette.Window,          QColor(d['window']))
    p.setColor(QPalette.WindowText,      QColor(d['text']))
    p.setColor(QPalette.Base,            QColor(d['base']))
    p.setColor(QPalette.AlternateBase,   QColor(d['alt_base']))
    p.setColor(QPalette.ToolTipBase,     QColor(d['tooltip_bg']))
    p.setColor(QPalette.ToolTipText,     QColor(d['text']))
    p.setColor(QPalette.Text,            QColor(d['text']))
    p.setColor(QPalette.Button,          QColor(d['button']))
    p.setColor(QPalette.ButtonText,      QColor(d['text']))
    p.setColor(QPalette.BrightText,      QColor(d['bright_text']))
    p.setColor(QPalette.Link,            QColor(d['link']))
    p.setColor(QPalette.Highlight,       QColor(d['accent']))
    p.setColor(QPalette.HighlightedText, QColor(d['accent_text']))
    p.setColor(QPalette.PlaceholderText, QColor(d['placeholder']))
    # Disabled state: muted text + a flat highlight so disabled rows don't glow.
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        p.setColor(QPalette.Disabled, role, QColor(d['disabled_text']))
    p.setColor(QPalette.Disabled, QPalette.Highlight, QColor(d['disabled_hl']))
    p.setColor(QPalette.Disabled, QPalette.HighlightedText,
               QColor(d['disabled_text']))
    return p


# Supplemental QSS for what QPalette doesn't style cleanly under Fusion. Kept
# intentionally tiny — the palette does the heavy lifting.
_DARK_QSS = (
    'QToolTip {{ color: {text}; background-color: {tooltip_bg}; '
    'border: 1px solid {border}; }}'
).format(**DARK)


def theme_qss(name: str) -> str:
    """The supplemental stylesheet for ``name`` ('' for non-dark themes)."""
    return _DARK_QSS if name == 'dark' else ''


# ── reusable-widget chrome (single source for gui/ui_components.py) ───────────────
# Accent button colours (base, hover, pressed) — coloured buttons read well on
# both light and dark, so they are theme-independent.
ACCENT = {
    'primary': ('#0078d4', '#006bc1', '#005ea2'),
    'danger':  ('#d32f2f', '#b71c1c', '#7f0000'),
    'success': ('#2e7d32', '#1b5e20', '#155218'),
}

# Per-mode chrome for the neutral widgets (secondary button, group-box border,
# disabled button). 'light' mirrors the historical hardcoded values exactly, so
# the 'system'/'light' look is byte-identical to before this refactor.
_CHROME = {
    'light': {
        'secondary_bg': '#f5f5f5', 'secondary_text': '#333333',
        'secondary_border': '#cccccc', 'secondary_hover': '#e0e0e0',
        'group_border': '#cccccc',
        'btn_disabled_bg': '#cccccc', 'btn_disabled_text': '#666666',
        'chart_label': '#333333', 'chart_header': '#444444',
    },
    'dark': {
        'secondary_bg': '#333337', 'secondary_text': '#d4d4d4',
        'secondary_border': '#3c3c3c', 'secondary_hover': '#3f3f46',
        'group_border': '#3c3c3c',
        'btn_disabled_bg': '#2a2a2a', 'btn_disabled_text': '#6d6d6d',
        'chart_label': '#d4d4d4', 'chart_header': '#9aa0a6',
    },
}


def is_dark(app=None) -> bool:
    """Whether a dark palette is active (read from the live QApplication).

    Detects from the palette (Window lightness) rather than a stored flag, so it
    is correct no matter who installed the palette. Safe to call with no app."""
    from qtpy.QtWidgets import QApplication
    app = app or QApplication.instance()
    if app is None:
        return False
    return app.palette().color(QPalette.Window).lightness() < 128


def chrome() -> dict:
    """The chrome colour set for the currently active theme."""
    return _CHROME['dark'] if is_dark() else _CHROME['light']


def button_qss(style: str) -> str:
    """Stylesheet for a ``StyledButton`` of ``style`` under the active theme."""
    ch = chrome()
    if style == 'secondary':
        return (
            f'QPushButton {{ background-color: {ch["secondary_bg"]}; '
            f'color: {ch["secondary_text"]}; '
            f'border: 1px solid {ch["secondary_border"]}; border-radius: 4px; '
            f'padding: 8px 16px; font-size: 13px; }}'
            f'QPushButton:hover {{ background-color: {ch["secondary_hover"]}; }}'
        )
    base, hover, pressed = ACCENT.get(style, ACCENT['primary'])
    return (
        f'QPushButton {{ background-color: {base}; color: white; border: none; '
        f'border-radius: 4px; padding: 8px 16px; font-size: 13px; '
        f'font-weight: 500; }}'
        f'QPushButton:hover {{ background-color: {hover}; }}'
        f'QPushButton:pressed {{ background-color: {pressed}; }}'
        f'QPushButton:disabled {{ background-color: {ch["btn_disabled_bg"]}; '
        f'color: {ch["btn_disabled_text"]}; }}'
    )


def group_box_qss() -> str:
    """Stylesheet for a ``SectionGroupBox`` under the active theme."""
    ch = chrome()
    return (
        f'QGroupBox {{ font-weight: bold; font-size: 13px; '
        f'border: 1px solid {ch["group_border"]}; border-radius: 6px; '
        f'margin-top: 12px; padding-top: 8px; }}'
        f'QGroupBox::title {{ subcontrol-origin: margin; left: 10px; '
        f'padding: 0 5px; }}'
    )


# ── theme-aware risk / severity text colours (F6 polish) ──────────────────────────
# The report palettes (core.executive_summary.RISK_COLORS, LIGHT_SEVERITY below)
# are tuned for a LIGHT background, so several are too dark to read as TEXT on the
# dark theme (e.g. risk 'Low'/'Clean' = #2e7d32 green, severity 'critical' =
# #8b0000). These accessors return brighter variants under the dark theme while
# leaving the light look — and the offline HTML reports, which keep using the core
# palettes directly — unchanged.

# Severity → cell colour on a LIGHT background (the canonical source; the GUI
# tabs and core report share these values). 'info' is muted.
LIGHT_SEVERITY = {
    'critical': '#8b0000', 'high': '#d13438', 'medium': '#ca5010',
    'low': '#0078d4', 'info': '#888888',
}
_DARK_SEVERITY = {
    'critical': '#ff5252', 'high': '#ef5350', 'medium': '#ffa726',
    'low': '#42a5f5', 'info': '#9e9e9e',
}
# Risk verdict → text colour on the dark theme (brighter than RISK_COLORS).
_DARK_RISK = {
    'Critical': '#ff5252', 'High': '#ff7043', 'Medium': '#ffb300',
    'Low': '#66bb6a', 'Clean': '#66bb6a',
}


def severity_color(severity: str):
    """Cell/text colour for a finding ``severity`` under the active theme.

    Returns ``None`` for an unknown severity (callers skip colouring), matching
    the previous ``_SEVERITY_COLORS.get(...)`` behaviour."""
    key = (severity or '').lower()
    return (_DARK_SEVERITY if is_dark() else LIGHT_SEVERITY).get(key)


def risk_color(level: str):
    """Text colour for a risk ``level`` under the active theme (``None`` if
    unknown — callers apply their own fallback, usually '#888')."""
    if is_dark():
        return _DARK_RISK.get(level)
    from core.executive_summary import RISK_COLORS
    return RISK_COLORS.get(level)


def apply_theme(app, name: str) -> str:
    """Apply theme ``name`` to the ``QApplication`` ``app``.

    Always sets the Fusion style (uniform base across platforms). ``'dark'``
    installs the dark palette + supplemental QSS; ``'system'``/``'light'`` (and
    any unknown value) restore Fusion's standard palette and clear the QSS, so
    toggling back at runtime fully reverts the look. Returns the name actually
    applied.
    """
    if name not in THEMES:
        name = DEFAULT_THEME
    app.setStyle('Fusion')
    if name == 'dark':
        app.setPalette(dark_palette())
        app.setStyleSheet(theme_qss('dark'))
    else:
        app.setPalette(app.style().standardPalette())
        app.setStyleSheet('')
    _apply_fluent_theme(name)
    return name


def _apply_fluent_theme(name: str) -> None:
    """Keep qfluentwidgets' own theme in step with ours (variant B, P3a).

    'system' maps to qfluent AUTO (follow OS); 'dark'/'light' map straight
    across. Guarded so a theming hiccup never blocks startup — the Fusion
    palette above still stands.
    """
    from gui._fluent import Theme, setTheme
    mapping = {'dark': Theme.DARK, 'light': Theme.LIGHT, 'system': Theme.AUTO}
    try:
        setTheme(mapping.get(name, Theme.AUTO))
    except Exception:   # noqa: BLE001 — cosmetic; never fail app startup over it
        pass
