"""gui/theme.py — single source of truth for the application's visual theme (F6).

The current GUI runs on PySide6 through qtpy/qfluent. The whole app is themed at
once via the Fusion style + a ``QPalette`` (plus a tiny supplemental QSS for what
the palette doesn't reach, e.g. tooltips), applied once on the ``QApplication`` —
so no per-tab stylesheet sweep is needed.

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

# Dark palette — the single source of chrome colours. Tuned for a calm, layered
# security/productivity look: a deep neutral (not pure-black) content surface,
# with the nav rail a touch darker and cards/rows a step lighter, so blocks read
# as distinct surfaces instead of one flat grey.
DARK = {
    # Surfaces, darkest → lightest (each step is a readable tone apart).
    'sidebar':       '#191a1d',   # left nav rail — slightly recessed
    'base':          '#1c1d21',   # inputs / tables / editors background
    'window':        '#202125',   # main content background
    'card':          '#26282d',   # sections / cards / alternating rows — lifts off
    'alt_base':      '#26282d',
    'header_bg':     '#23242a',   # table header strip
    'hover':         '#2c2e34',   # hover state on rows / nav items
    # Text.
    'text':          '#e3e3e6',
    'muted_text':    '#9aa0a6',
    'disabled_text': '#6d6d6d',
    'placeholder':   '#7c8087',
    # Accent / interaction.
    'accent':        '#0078d4',   # selection / focus accent (calm blue)
    'accent_text':   '#ffffff',
    'selection':     '#2d4f76',   # table row selection bg — visible, not shouting
    'button':        '#2c2e33',
    'bright_text':   '#ff5252',
    'link':          '#5cc8ff',
    # Lines / chrome.
    'border':        '#34363b',
    'input_border':  '#3a3d44',
    'scrollbar':     '#3a3d44',
    'scrollbar_hover': '#4a4e57',
    'tooltip_bg':    '#2a2c31',
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


# Supplemental QSS for what QPalette doesn't style cleanly under Fusion — tables,
# inputs, editors and scrollbars — so content reads as calm, distinct blocks
# rather than one flat tone. The palette still does the base lift; this only adds
# borders, surfaces, hover/selection and slim scrollbars. Scoped to standard Qt
# widgets used in tabs; StyledButton / SectionGroupBox keep owning their own look
# (see button_qss / group_box_qss), and window controls are untouched.
def _build_dark_qss() -> str:
    d = DARK
    return f"""
    QToolTip {{ color: {d['text']}; background-color: {d['tooltip_bg']};
        border: 1px solid {d['border']}; padding: 4px 6px; }}

    /* Text inputs / selectors — recessed surface, subtle border, accent focus. */
    QLineEdit, QComboBox, QAbstractSpinBox, QPlainTextEdit, QTextEdit, QTextBrowser {{
        background-color: {d['base']}; color: {d['text']};
        border: 1px solid {d['input_border']}; border-radius: 5px;
        selection-background-color: {d['accent']}; selection-color: {d['accent_text']};
        padding: 3px 6px; }}
    QLineEdit:focus, QComboBox:focus, QAbstractSpinBox:focus,
    QPlainTextEdit:focus, QTextEdit:focus {{ border: 1px solid {d['accent']}; }}
    QComboBox QAbstractItemView {{ background-color: {d['card']}; color: {d['text']};
        border: 1px solid {d['border']};
        selection-background-color: {d['selection']}; }}

    /* Tables — readable header strip, gridlines, alternating rows and selection. */
    QTableView, QTableWidget, QTreeView, QListView {{
        background-color: {d['base']}; alternate-background-color: {d['card']};
        gridline-color: {d['border']};
        selection-background-color: {d['selection']}; selection-color: {d['text']};
        border: 1px solid {d['border']}; border-radius: 6px; }}
    QTableView::item, QTreeView::item, QListView::item {{ padding: 2px 4px; }}
    QTableView::item:hover, QTreeView::item:hover, QListView::item:hover {{
        background-color: {d['hover']}; }}
    QHeaderView::section {{ background-color: {d['header_bg']}; color: {d['muted_text']};
        border: none; border-bottom: 1px solid {d['border']};
        border-right: 1px solid {d['border']}; padding: 5px 8px; font-weight: 600; }}
    QTableCornerButton::section {{ background-color: {d['header_bg']};
        border: none; border-bottom: 1px solid {d['border']}; }}

    /* Tab panes (QTabWidget facades inside tabs). */
    QTabWidget::pane {{ border: 1px solid {d['border']}; border-radius: 6px;
        top: -1px; }}
    QTabBar::tab {{ background: {d['base']}; color: {d['muted_text']};
        border: 1px solid {d['border']}; border-bottom: none;
        border-top-left-radius: 5px; border-top-right-radius: 5px;
        padding: 6px 12px; }}
    QTabBar::tab:selected {{ background: {d['card']}; color: {d['text']}; }}
    QTabBar::tab:hover {{ background: {d['hover']}; }}

    /* Slim, neutral scrollbars (wheel/drag both work; no arrow buttons). */
    QScrollBar:vertical {{ background: transparent; width: 12px; margin: 0; }}
    QScrollBar::handle:vertical {{ background: {d['scrollbar']}; min-height: 28px;
        border-radius: 6px; }}
    QScrollBar::handle:vertical:hover {{ background: {d['scrollbar_hover']}; }}
    QScrollBar:horizontal {{ background: transparent; height: 12px; margin: 0; }}
    QScrollBar::handle:horizontal {{ background: {d['scrollbar']}; min-width: 28px;
        border-radius: 6px; }}
    QScrollBar::handle:horizontal:hover {{ background: {d['scrollbar_hover']}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
    """


_DARK_QSS = _build_dark_qss()


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


# Left navigation rail palette (gui/fluent_nav.py). Centralised here so the rail
# matches the layered theme instead of carrying its own hardcoded greys: a
# recessed surface, a clear hover, and an obvious selected item (accent left bar).
_NAV = {
    'dark': {
        'bg': DARK['sidebar'], 'border': DARK['border'], 'text': DARK['text'],
        'hover': DARK['hover'], 'selected_bg': DARK['card'],
        'accent': DARK['accent'], 'sep': DARK['border'],
    },
    'light': {
        'bg': '#f3f3f3', 'border': '#d6d6d6', 'text': '#1f1f1f',
        'hover': '#e7e7e7', 'selected_bg': '#e4eef9',
        'accent': '#0078d4', 'sep': '#d6d6d6',
    },
}


def navigation_qss() -> str:
    """Stylesheet for the left nav rail under the active theme.

    Targets ``QFrame#stableNavigation`` / ``QPushButton[navItem]`` /
    ``QFrame[navSep]`` so fluent_nav doesn't hardcode colours; selected items get
    an accent left bar (kept obvious), hover a subtle lift."""
    c = _NAV['dark'] if is_dark() else _NAV['light']
    return f"""
    QFrame#stableNavigation {{ background: {c['bg']};
        border-right: 1px solid {c['border']}; }}
    QPushButton[navItem="true"] {{ background: transparent; border: 0;
        border-radius: 6px; color: {c['text']}; font-size: 14px;
        padding: 10px 12px; text-align: left; }}
    QPushButton[navItem="true"]:hover {{ background: {c['hover']}; }}
    QPushButton[navItem="true"]:checked {{ background: {c['selected_bg']};
        border-left: 3px solid {c['accent']}; padding-left: 9px;
        font-weight: 600; }}
    QFrame[navSep="true"] {{ color: {c['sep']}; background: {c['sep']};
        max-height: 1px; border: 0; }}
    QScrollArea {{ background: transparent; border: 0; }}
    """


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
