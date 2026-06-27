import os

from qtpy.QtCore import Qt
from qtpy.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QHBoxLayout, QLabel, QLineEdit, QMessageBox, QSpinBox,
    QPlainTextEdit, QScrollArea, QTabWidget, QVBoxLayout, QWidget,
)

from core import alerts as alert_center
from core import config
from core.llm_summary import DEFAULT_MODEL as _OLLAMA_DEFAULT_MODEL
from gui.theme import THEMES
from gui.ui_components import SectionGroupBox, StyledButton
from utils.browser_utils import BROWSER_HEADERS

# User-Agent profiles the request layer (SessionBuilder) actually supports.
_UA_PROFILES = list(BROWSER_HEADERS.keys())
_ARCHIVE_FORMATS = ['zip', 'rar']
# (gui_theme value -> RU label) for the appearance selector.
_THEME_LABELS = {'system': 'Системная', 'light': 'Светлая', 'dark': 'Тёмная'}

# (alert type -> RU label) for the Notifications tab. Module-level so a test can
# assert it covers every alert_center.ALERT_TYPES (an unlabelled type would show
# as its raw key). Labels mirror gui.tab_timeline._EVENT_LABELS where they overlap.
_ALERT_TYPE_LABELS = {
    'new_secret': 'Новый секрет',
    'new_secret_generic': 'Новый секрет (generic)',
    'new_subdomain': 'Новый субдомен',
    'takeover': 'Takeover', 'new_technology': 'Новая технология',
    'cert_change': 'Смена сертификата', 'risk_increase': 'Рост риска',
    'cert_expired': 'Сертификат истёк',
    'graphql_introspection': 'GraphQL introspection',
    'new_sourcemap': 'Утёкший source map',
    'cookie_weakened': 'Cookie ослаблена',
    'new_vulnerable_dependency': 'Уязвимая зависимость',
    'dependency_vulnerable': 'Зависимость стала уязвимой',
    'security_header_removed': 'Security-заголовок убран',
    'sla_breach': 'Просрочка SLA',
    'new_finding': 'Новая находка',
    'dns_email_auth_weakened': 'Email-auth ослаблен (SPF/DMARC)',
    'new_attack_path': 'Новый attack path',
    'attack_path_escalated': 'Attack path усилился',
    'attack_surface_drift': 'Дрейф: attack surface ↑',
    'exposure_drift': 'Дрейф: экспозиция ↑',
    'criticality_drift': 'Дрейф: критичные активы ↑',
}


class SettingsDialog(QDialog):
    """Диалог настроек приложения"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки")
        self.setMinimumSize(500, 380)
        # Open large enough that the tallest tab (Уведомления: Email/Telegram/
        # Discord/Webhook + test) fits without scrolling; each tab is still
        # wrapped in a QScrollArea so smaller windows degrade gracefully.
        self.resize(580, 600)
        self.settings = config.load_settings()
        self._build_ui()

    def _save_settings(self):
        config.save_settings(self.settings)

    def _build_ui(self):
        layout = QVBoxLayout(self)

        tabs = QTabWidget()
        tabs.addTab(self._scroll_tab(self._build_paths_tab()), "Пути")
        tabs.addTab(self._scroll_tab(self._build_network_tab()), "Сеть")
        tabs.addTab(self._scroll_tab(self._build_output_tab()), "Вывод")
        tabs.addTab(self._scroll_tab(self._build_alerts_tab()), "Уведомления")
        tabs.addTab(self._scroll_tab(self._build_dependencies_tab()), "Зависимости")
        layout.addWidget(tabs)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @staticmethod
    def _scroll_tab(widget: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setWidget(widget)
        return scroll

    def _build_paths_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        group = SectionGroupBox("Директория для сохранения результатов")
        g_layout = QHBoxLayout()
        self.output_dir_edit = QLineEdit(self.settings.get('output_dir', ''))
        browse_btn = StyledButton("Обзор...", style='secondary')
        browse_btn.clicked.connect(self._browse_output_dir)
        g_layout.addWidget(self.output_dir_edit)
        g_layout.addWidget(browse_btn)
        group.setLayout(g_layout)

        layout.addWidget(group)
        layout.addStretch()
        return widget

    def _build_dependencies_tab(self) -> QWidget:
        """Read-only dependency/system-health view.

        This replaces the startup health popup: users can inspect required and
        optional components from Settings whenever they need it.
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)

        layout.addWidget(QLabel(
            "Проверка окружения и опциональных компонентов. "
            "Отсутствующие опциональные зависимости отключают только связанные функции."
        ))

        self.dependencies_hint = layout.itemAt(layout.count() - 1).widget()
        self.dependencies_hint.setObjectName("dependenciesHint")
        self.dependencies_hint.setWordWrap(True)

        self.dependencies_text = QPlainTextEdit()
        self.dependencies_text.setReadOnly(True)
        self.dependencies_text.setMinimumHeight(260)
        layout.addWidget(self.dependencies_text, 1)

        refresh_btn = StyledButton("Обновить проверку", style='secondary')
        refresh_btn.clicked.connect(self._refresh_dependencies)
        layout.addWidget(refresh_btn)

        self._refresh_dependencies()
        return widget

    def _build_network_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        group = SectionGroupBox("Параметры запросов")
        g_layout = QVBoxLayout()

        g_layout.addWidget(QLabel("Макс. страниц для сканирования:"))
        self.max_pages_spin = QSpinBox()
        self.max_pages_spin.setRange(1, 500)
        self.max_pages_spin.setValue(self.settings.get('max_pages', 50))
        g_layout.addWidget(self.max_pages_spin)

        g_layout.addWidget(QLabel("Задержка между запросами (мс):"))
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 10000)
        self.delay_spin.setSingleStep(100)
        self.delay_spin.setValue(self.settings.get('request_delay', 500))
        g_layout.addWidget(self.delay_spin)

        g_layout.addWidget(QLabel("Профиль User-Agent:"))
        self.ua_combo = QComboBox()
        self.ua_combo.addItems(_UA_PROFILES)
        current_ua = self.settings.get('user_agent_profile', 'chrome_windows')
        if current_ua in _UA_PROFILES:
            self.ua_combo.setCurrentText(current_ua)
        g_layout.addWidget(self.ua_combo)

        g_layout.addWidget(QLabel("Модель локального Ollama (AI-резюме):"))
        self.ollama_model_edit = QLineEdit(self.settings.get('ollama_model', ''))
        self.ollama_model_edit.setPlaceholderText(_OLLAMA_DEFAULT_MODEL)
        self.ollama_model_edit.setToolTip(
            "Имя модели для опц. AI-резюме через локальный Ollama "
            f"(по умолчанию '{_OLLAMA_DEFAULT_MODEL}'). Пусто = модель по умолчанию.")
        g_layout.addWidget(self.ollama_model_edit)

        g_layout.addWidget(QLabel("Кеш сканирования (GeoIP + пассивные субдомены):"))
        btn_clear_cache = StyledButton("Очистить кеш", style='secondary')
        btn_clear_cache.setToolTip(
            "Сбрасывает TTL-кеш GeoIP и пассивного перечисления субдоменов,\n"
            "чтобы следующий скан пошёл в сеть за свежими данными."
        )
        btn_clear_cache.clicked.connect(self._clear_cache)
        g_layout.addWidget(btn_clear_cache)

        group.setLayout(g_layout)
        layout.addWidget(group)
        layout.addStretch()
        return widget

    def _build_output_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        group = SectionGroupBox("Архивация")
        g_layout = QVBoxLayout()
        self.auto_compress_cb = QCheckBox("Авто-архивация результатов")
        self.auto_compress_cb.setChecked(self.settings.get('auto_compress', False))
        g_layout.addWidget(self.auto_compress_cb)

        g_layout.addWidget(QLabel("Формат архива:"))
        self.compress_combo = QComboBox()
        self.compress_combo.addItems(_ARCHIVE_FORMATS)
        current_fmt = self.settings.get('compression_format', 'zip')
        if current_fmt in _ARCHIVE_FORMATS:
            self.compress_combo.setCurrentText(current_fmt)
        self.compress_combo.setToolTip(
            "RAR требует winrar/rar в PATH; иначе автоматически используется ZIP."
        )
        g_layout.addWidget(self.compress_combo)
        group.setLayout(g_layout)
        layout.addWidget(group)

        # Appearance / theme (F6) — opt-in; applied live on OK.
        theme_grp = SectionGroupBox("Оформление")
        tl = QVBoxLayout()
        tl.addWidget(QLabel("Тема интерфейса:"))
        self.theme_combo = QComboBox()
        for value in THEMES:
            self.theme_combo.addItem(_THEME_LABELS.get(value, value), value)
        current_theme = self.settings.get('gui_theme', 'system')
        idx = self.theme_combo.findData(current_theme)
        if idx >= 0:
            self.theme_combo.setCurrentIndex(idx)
        self.theme_combo.setToolTip(
            "«Тёмная» включает тёмную палитру всего приложения. Применяется "
            "сразу; для виджетов со своими стилями полный эффект — после "
            "перезапуска.")
        tl.addWidget(self.theme_combo)
        theme_grp.setLayout(tl)
        layout.addWidget(theme_grp)

        layout.addStretch()
        return widget

    def _build_alerts_tab(self) -> QWidget:
        """Alert Center (#9) channel config. Lives in settings.json; this is a
        thin editor over it. Sending uses core.alerts (stdlib, opt-in)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        cfg = self.settings.get('alerts') or {}

        self.alerts_enabled_cb = QCheckBox("Включить уведомления (Alert Center)")
        self.alerts_enabled_cb.setChecked(bool(cfg.get('enabled')))
        self.alerts_enabled_cb.setToolTip(
            "Строго opt-in. При мониторинге шлёт уведомления об изменениях "
            "(новый секрет/субдомен/takeover/технология/смена сертификата/рост риска).")
        layout.addWidget(self.alerts_enabled_cb)

        # Event-type filter (unchecked-all = send every type).
        types_grp = SectionGroupBox("Типы событий (ничего не отмечено = все)")
        tg_layout = QVBoxLayout()
        self._alert_type_cbs = {}
        enabled_types = set(cfg.get('types') or [])
        for key in alert_center.ALERT_TYPES:
            cb = QCheckBox(_ALERT_TYPE_LABELS.get(key, key))
            cb.setChecked(key in enabled_types)
            self._alert_type_cbs[key] = cb
            tg_layout.addWidget(cb)
        types_grp.setLayout(tg_layout)
        layout.addWidget(types_grp)

        tg = cfg.get('telegram') or {}
        tg_grp = SectionGroupBox("Telegram")
        tgl = QVBoxLayout()
        self.alert_tg_token = QLineEdit(tg.get('token', ''))
        self.alert_tg_token.setPlaceholderText("Bot token")
        self.alert_tg_chat = QLineEdit(tg.get('chat_id', ''))
        self.alert_tg_chat.setPlaceholderText("Chat ID")
        tgl.addWidget(self.alert_tg_token)
        tgl.addWidget(self.alert_tg_chat)
        tg_grp.setLayout(tgl)
        layout.addWidget(tg_grp)

        dc = cfg.get('discord') or {}
        dc_grp = SectionGroupBox("Discord")
        dcl = QVBoxLayout()
        self.alert_dc_webhook = QLineEdit(dc.get('webhook_url', ''))
        self.alert_dc_webhook.setPlaceholderText("Webhook URL")
        dcl.addWidget(self.alert_dc_webhook)
        dc_grp.setLayout(dcl)
        layout.addWidget(dc_grp)

        wh = cfg.get('webhook') or {}
        wh_grp = SectionGroupBox("Webhook (generic)")
        whl = QVBoxLayout()
        self.alert_wh_url = QLineEdit(wh.get('url', ''))
        self.alert_wh_url.setPlaceholderText(
            "HTTPS endpoint (Slack/Teams/Zapier/n8n/свой) — JSON {text, subject, body}")
        whl.addWidget(self.alert_wh_url)
        wh_grp.setLayout(whl)
        layout.addWidget(wh_grp)

        em = cfg.get('email') or {}
        em_grp = SectionGroupBox("Email (SMTP)")
        eml = QVBoxLayout()
        self.alert_em_host = QLineEdit(em.get('host', ''))
        self.alert_em_host.setPlaceholderText("SMTP host")
        self.alert_em_port = QSpinBox()
        self.alert_em_port.setRange(1, 65535)
        self.alert_em_port.setValue(int(em.get('port', 587)))
        self.alert_em_user = QLineEdit(em.get('username', ''))
        self.alert_em_user.setPlaceholderText("Username (опц.)")
        self.alert_em_pass = QLineEdit(em.get('password', ''))
        self.alert_em_pass.setEchoMode(QLineEdit.Password)
        self.alert_em_pass.setPlaceholderText("Password (опц.)")
        self.alert_em_from = QLineEdit(em.get('from', ''))
        self.alert_em_from.setPlaceholderText("From")
        self.alert_em_to = QLineEdit(em.get('to', ''))
        self.alert_em_to.setPlaceholderText("To")
        self.alert_em_tls = QCheckBox("STARTTLS")
        self.alert_em_tls.setChecked(bool(em.get('tls', True)))
        row_hp = QHBoxLayout()
        row_hp.addWidget(self.alert_em_host)
        row_hp.addWidget(QLabel("Порт:"))
        row_hp.addWidget(self.alert_em_port)
        eml.addLayout(row_hp)
        eml.addWidget(self.alert_em_user)
        eml.addWidget(self.alert_em_pass)
        eml.addWidget(self.alert_em_from)
        eml.addWidget(self.alert_em_to)
        eml.addWidget(self.alert_em_tls)
        em_grp.setLayout(eml)
        layout.addWidget(em_grp)

        btn_test = StyledButton("Отправить тестовое уведомление", style='secondary')
        btn_test.clicked.connect(self._test_alerts)
        layout.addWidget(btn_test)
        layout.addStretch()
        return widget

    def _collect_alerts_config(self) -> dict:
        """Assemble the alerts config dict from the tab's fields."""
        cfg = {
            'enabled': self.alerts_enabled_cb.isChecked(),
            'types': [k for k, cb in self._alert_type_cbs.items()
                      if cb.isChecked()],
            'telegram': {'token': self.alert_tg_token.text().strip(),
                         'chat_id': self.alert_tg_chat.text().strip()},
            'discord': {'webhook_url': self.alert_dc_webhook.text().strip()},
            'webhook': {'url': self.alert_wh_url.text().strip()},
            'email': {'host': self.alert_em_host.text().strip(),
                      'port': self.alert_em_port.value(),
                      'username': self.alert_em_user.text().strip(),
                      'password': self.alert_em_pass.text(),
                      'from': self.alert_em_from.text().strip(),
                      'to': self.alert_em_to.text().strip(),
                      'tls': self.alert_em_tls.isChecked()},
        }
        return cfg

    def _test_alerts(self):
        """Send a test message to every configured channel and report back."""
        out = alert_center.send_test(self._collect_alerts_config())
        if out.get('reason'):
            QMessageBox.warning(self, "Уведомления",
                                f"Не отправлено: {out['reason']}.\n"
                                "Заполните хотя бы один канал.")
            return
        lines = [f"{r.get('channel')}: {r.get('status')}"
                 + (f" — {r['error']}" if r.get('error') else '')
                 for r in out.get('results', [])]
        QMessageBox.information(
            self, "Уведомления",
            f"Отправлено каналов: {out['sent']}\n" + "\n".join(lines))

    def _refresh_dependencies(self):
        """Refresh the dependency health text in the Settings dialog."""
        from core.launcher import health_check
        from gui.first_run import health_report_text

        self.dependencies_text.setPlainText(health_report_text(health_check()))

    def _clear_cache(self):
        """Сбросить кеши сканирования: in-memory TTL (GeoIP + пассивные субдомены
        + ASN-разведка + OSV-корреляция) и персистентный CVE-кеш (OSV/NVD)."""
        from core.asn_intel import clear_cache as clear_asn_cache
        from core.cve_intel import clear_cache as clear_cve_cache
        from core.osv_correlation import clear_cache as clear_osv_cache
        from core.recon_engine import clear_geo_cache
        from core.subdomain_scanner import clear_passive_cache
        n = (clear_geo_cache() + clear_passive_cache() + clear_asn_cache()
             + clear_osv_cache() + clear_cve_cache())
        QMessageBox.information(self, "Кеш", f"Очищено записей кеша: {n}")

    def _browse_output_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Выберите папку", self.output_dir_edit.text())
        if path:
            self.output_dir_edit.setText(path)

    def _on_accept(self):
        # Expand ~ on save so an in-session scan never writes to a literal
        # "~" folder in the CWD (load_settings expands too, but only on next
        # launch — this closes the same-session gap).
        self.settings['output_dir'] = os.path.expanduser(
            self.output_dir_edit.text())
        self.settings['max_pages'] = self.max_pages_spin.value()
        self.settings['request_delay'] = self.delay_spin.value()
        self.settings['user_agent_profile'] = self.ua_combo.currentText()
        self.settings['ollama_model'] = self.ollama_model_edit.text().strip()
        self.settings['auto_compress'] = self.auto_compress_cb.isChecked()
        self.settings['compression_format'] = self.compress_combo.currentText()
        self.settings['gui_theme'] = self.theme_combo.currentData()
        self.settings['alerts'] = self._collect_alerts_config()
        self._save_settings()
        self._apply_theme_live()
        self.accept()

    def _apply_theme_live(self):
        """Apply the chosen theme to the running app immediately (F6)."""
        from qtpy.QtWidgets import QApplication

        from gui.theme import apply_theme
        app = QApplication.instance()
        if app is not None:
            apply_theme(app, self.settings.get('gui_theme', 'system'))

    def get_settings(self) -> dict:
        return self.settings.copy()
