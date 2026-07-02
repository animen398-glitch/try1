"""Alert Center (#9) — Settings dialog UI (headless Qt).

The Уведомления tab reflects the saved alerts config and collects channel/type
fields back into the config shape core.alerts expects.
"""


def test_every_alert_type_has_a_label():
    # Each alertable type needs a RU label, else the Notifications tab shows its
    # raw key. Guards against adding an ALERT_TYPE without labelling it.
    from core import alerts as alert_center
    from gui.dialogs import _ALERT_TYPE_LABELS
    missing = set(alert_center.ALERT_TYPES) - set(_ALERT_TYPE_LABELS)
    assert not missing, f'unlabelled alert types: {sorted(missing)}'


def test_alerts_tab_populates_from_settings(qapp, monkeypatch):
    from core import config
    monkeypatch.setattr(config, 'load_settings', lambda: {
        'output_dir': 'x',
        'alerts': {'enabled': True, 'types': ['takeover'],
                   'telegram': {'token': 'T', 'chat_id': 'C'},
                   'discord': {'webhook_url': 'https://d'}}})
    from gui.dialogs import SettingsDialog
    d = SettingsDialog()
    assert d.alerts_enabled_cb.isChecked()
    assert d.alert_tg_token.text() == 'T' and d.alert_tg_chat.text() == 'C'
    assert d.alert_dc_webhook.text() == 'https://d'
    assert d._alert_type_cbs['takeover'].isChecked()
    assert d._alert_type_cbs['new_secret'].isChecked() is False


def test_collect_alerts_config_round_trips(qapp, monkeypatch):
    from core import config
    monkeypatch.setattr(config, 'load_settings', lambda: {'output_dir': 'x',
                                                          'alerts': {}})
    from gui.dialogs import SettingsDialog
    d = SettingsDialog()
    d.alerts_enabled_cb.setChecked(True)
    d._alert_type_cbs['new_secret'].setChecked(True)
    d.alert_dc_webhook.setText('https://hook')
    d.alert_sl_webhook.setText('https://hooks.slack.com/services/x')
    d.alert_wh_url.setText('https://generic.hook/path')
    cfg = d._collect_alerts_config()
    assert cfg['enabled'] is True
    assert cfg['types'] == ['new_secret']
    assert cfg['discord'] == {'webhook_url': 'https://hook'}
    assert cfg['slack'] == {'webhook_url': 'https://hooks.slack.com/services/x'}   # WS4
    assert cfg['webhook'] == {'url': 'https://generic.hook/path'}   # F3
    assert cfg['email']['port'] == 587   # default carried


def test_alerts_tab_populates_webhook_from_settings(qapp, monkeypatch):
    from core import config
    monkeypatch.setattr(config, 'load_settings', lambda: {
        'output_dir': 'x',
        'alerts': {'webhook': {'url': 'https://generic.hook'}}})
    from gui.dialogs import SettingsDialog
    d = SettingsDialog()
    assert d.alert_wh_url.text() == 'https://generic.hook'


def test_alerts_tab_populates_slack_from_settings(qapp, monkeypatch):
    from core import config
    monkeypatch.setattr(config, 'load_settings', lambda: {
        'output_dir': 'x',
        'alerts': {'slack': {'webhook_url': 'https://hooks.slack.com/services/y'}}})
    from gui.dialogs import SettingsDialog
    d = SettingsDialog()
    assert d.alert_sl_webhook.text() == 'https://hooks.slack.com/services/y'


def test_test_button_calls_send_test(qapp, monkeypatch):
    from core import config
    monkeypatch.setattr(config, 'load_settings', lambda: {'output_dir': 'x',
                                                          'alerts': {}})
    import gui.dialogs as dlg
    seen = {}
    monkeypatch.setattr(dlg.alert_center, 'send_test',
                        lambda c: (seen.update(cfg=c),
                                   {'sent': 1, 'results': [
                                       {'channel': 'discord', 'status': 'ok'}]})[1])
    monkeypatch.setattr(dlg.QMessageBox, 'information',
                        staticmethod(lambda *a, **k: None))
    d = dlg.SettingsDialog()
    d.alert_dc_webhook.setText('https://hook')
    d._test_alerts()
    assert seen['cfg']['discord']['webhook_url'] == 'https://hook'
