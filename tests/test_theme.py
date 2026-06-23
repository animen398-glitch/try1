"""GUI theme core (gui/theme.py, F6 T6.1/T6.2) — headless, thread-free.

Verifies the palette engine and the opt-in default wiring. ``apply_theme``
mutates the shared session QApplication, so each test that changes it restores
the original palette/stylesheet afterwards to avoid leaking a dark palette into
other GUI tests.
"""

from contextlib import contextmanager

from qtpy.QtGui import QPalette

from core.config import DEFAULT_SETTINGS
from gui import theme


@contextmanager
def _restore(app):
    pal, qss = app.palette(), app.styleSheet()
    try:
        yield
    finally:
        app.setPalette(pal)
        app.setStyleSheet(qss)


# ── module shape / defaults ───────────────────────────────────────────────────────

def test_themes_membership():
    assert theme.THEMES == ('system', 'light', 'dark')
    assert theme.DEFAULT_THEME == 'system'


def test_default_setting_is_system_optin():
    # The default must leave the current look untouched (stability #1).
    assert DEFAULT_SETTINGS['gui_theme'] == 'system'


def test_theme_qss_only_for_dark():
    assert theme.theme_qss('dark')               # non-empty
    assert theme.theme_qss('system') == ''
    assert theme.theme_qss('light') == ''


def test_dark_palette_is_dark():
    pal = theme.dark_palette()
    assert pal.color(QPalette.Window).lightness() < 128
    assert pal.color(QPalette.WindowText).lightness() > 128   # light text


# ── apply_theme ───────────────────────────────────────────────────────────────────

def test_apply_dark_sets_dark_palette(qapp):
    with _restore(qapp):
        applied = theme.apply_theme(qapp, 'dark')
        assert applied == 'dark'
        assert qapp.palette().color(QPalette.Window).lightness() < 128
        assert qapp.styleSheet()                 # supplemental QSS installed


def test_apply_system_reverts(qapp):
    with _restore(qapp):
        theme.apply_theme(qapp, 'dark')          # go dark first
        applied = theme.apply_theme(qapp, 'system')
        assert applied == 'system'
        assert qapp.palette().color(QPalette.Window).lightness() > 128
        assert qapp.styleSheet() == ''


def test_apply_unknown_falls_back_to_default(qapp):
    with _restore(qapp):
        assert theme.apply_theme(qapp, 'neon') == 'system'


# ── settings dialog wiring ────────────────────────────────────────────────────────

# ── reusable-widget chrome (T6.3) ─────────────────────────────────────────────────

def test_button_qss_accent_is_theme_independent(qapp):
    with _restore(qapp):
        theme.apply_theme(qapp, 'system')
        light = theme.button_qss('primary')
        theme.apply_theme(qapp, 'dark')
        dark = theme.button_qss('primary')
        # Accent buttons keep their colour in both themes …
        assert '#0078d4' in light and '#0078d4' in dark
        # … but the disabled background follows the theme.
        assert '#cccccc' in light and '#2a2a2a' in dark


def test_button_qss_secondary_adapts_to_theme(qapp):
    with _restore(qapp):
        theme.apply_theme(qapp, 'system')
        assert '#f5f5f5' in theme.button_qss('secondary')      # light neutral
        theme.apply_theme(qapp, 'dark')
        assert '#333337' in theme.button_qss('secondary')      # dark neutral


def test_group_box_qss_border_adapts(qapp):
    with _restore(qapp):
        theme.apply_theme(qapp, 'system')
        assert '#cccccc' in theme.group_box_qss()
        theme.apply_theme(qapp, 'dark')
        assert '#3c3c3c' in theme.group_box_qss()


def test_navigation_qss_is_theme_aware(qapp):
    with _restore(qapp):
        theme.apply_theme(qapp, 'dark')
        dark = theme.navigation_qss()
        assert 'QFrame#stableNavigation' in dark
        assert theme.DARK['sidebar'] in dark          # recessed rail surface
        assert theme.DARK['accent'] in dark           # selected accent bar
        theme.apply_theme(qapp, 'system')
        light = theme.navigation_qss()
        assert '#f3f3f3' in light                      # light rail surface
        assert dark != light


def test_is_dark_and_chrome_track_palette(qapp):
    with _restore(qapp):
        theme.apply_theme(qapp, 'dark')
        assert theme.is_dark(qapp) is True
        assert theme.chrome()['chart_label'] == '#d4d4d4'
        theme.apply_theme(qapp, 'system')
        assert theme.is_dark(qapp) is False
        assert theme.chrome()['chart_label'] == '#333333'


def test_styled_widgets_build_under_dark(qapp):
    from gui.ui_components import SectionGroupBox, StyledButton
    with _restore(qapp):
        theme.apply_theme(qapp, 'dark')
        btn = StyledButton('x', style='secondary')
        grp = SectionGroupBox('s')
        try:
            assert '#333337' in btn.styleSheet()      # dark neutral applied
            assert '#3c3c3c' in grp.styleSheet()
        finally:
            btn.deleteLater()
            grp.deleteLater()


# ── theme-aware risk / severity colours (F6 polish) ───────────────────────────────

def test_severity_color_theme_aware(qapp):
    from qtpy.QtGui import QColor
    with _restore(qapp):
        theme.apply_theme(qapp, 'system')
        assert theme.severity_color('critical') == '#8b0000'
        assert theme.severity_color('CRITICAL') == '#8b0000'   # case-insensitive
        assert theme.severity_color('nope') is None            # unknown → skip
        theme.apply_theme(qapp, 'dark')
        # Dark variant is brighter (readable on a dark background).
        assert (QColor(theme.severity_color('critical')).lightness()
                > QColor('#8b0000').lightness())


def test_risk_color_theme_aware(qapp):
    from qtpy.QtGui import QColor

    from core.executive_summary import RISK_COLORS
    with _restore(qapp):
        theme.apply_theme(qapp, 'system')
        assert theme.risk_color('Low') == RISK_COLORS['Low']   # report palette
        assert theme.risk_color('nope') is None
        theme.apply_theme(qapp, 'dark')
        # The dark 'Low'/'Clean' green is brightened for contrast.
        assert (QColor(theme.risk_color('Low')).lightness()
                > QColor(RISK_COLORS['Low']).lightness())


def test_settings_dialog_has_theme_selector(qapp):
    from gui.dialogs import SettingsDialog
    dlg = SettingsDialog()
    try:
        values = [dlg.theme_combo.itemData(i)
                  for i in range(dlg.theme_combo.count())]
        assert values == list(theme.THEMES)
        # Selection reflects the current setting (default 'system').
        assert dlg.theme_combo.currentData() in theme.THEMES
    finally:
        dlg.deleteLater()
