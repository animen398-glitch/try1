"""Engagements GUI tab — headless thin-surface tests (S4)."""

from core import engagement as eng
from core import pentest_mission as pm
from core.engagement_store import EngagementStore
from core.mission_store import MissionStore
from gui.plugin_manager import default_manager
from gui.tab_engagement import EngagementsTabMixin
from tests.gui_test_helpers import EngagementsHost


def _save(client="Acme", project="shop.com", **kw):
    return EngagementStore().save_engagement(
        eng.create_engagement(client, project, **kw))


def test_tab_builds_with_columns(qapp):
    w = EngagementsHost()
    assert hasattr(w, "_engagement_widget")
    assert w.engagement_table.columnCount() == len(EngagementsTabMixin.ENGAGEMENT_COLUMNS)
    assert not w.btn_engagement_advance.isEnabled()


def test_engagements_registered_in_tab_bar(qapp):
    assert "Engagements" in [p.title for p in default_manager()]


def test_query_projects_lists_engagement_projects(qapp):
    _save("Acme", "shop.com")
    _save("Beta", "bank.example")
    out = EngagementsTabMixin._query_engagement_projects()
    assert "error" not in out
    assert {"shop.com", "bank.example"} <= set(out["projects"])


def test_populate_and_select_shows_detail_and_targets(qapp):
    _save("Acme", "shop.com", authorization={"accepted": True})
    w = EngagementsHost()
    w._populate_engagements(EngagementsTabMixin._query_engagements("shop.com"))
    assert w.engagement_table.rowCount() == 1
    w.engagement_table.selectRow(0)
    detail = w.engagement_detail.toPlainText()
    assert "Acme" in detail
    # draft → authorized/archived legal targets
    targets = {w.engagement_advance_status.itemData(i)
               for i in range(w.engagement_advance_status.count())}
    assert targets == {"authorized", "archived"}
    assert w.btn_engagement_advance.isEnabled()


def test_do_advance_persists(qapp):
    saved = _save("Acme", "shop.com", authorization={"accepted": True})
    out = EngagementsTabMixin._do_advance_engagement(saved["payload"], "authorized")
    assert "error" not in out
    assert EngagementStore().get_engagement(saved["id"])["status"] == "authorized"


def test_do_advance_illegal_reports_error(qapp):
    saved = _save("Acme", "shop.com")          # draft, not accepted
    out = EngagementsTabMixin._do_advance_engagement(saved["payload"], "active")
    assert "error" in out                       # draft cannot jump to active
    out2 = EngagementsTabMixin._do_advance_engagement(saved["payload"], "authorized")
    assert "error" in out2                       # authorization not accepted


def test_do_link_engagement_checked(qapp):
    saved = _save("Acme", "shop.com")
    mid = MissionStore().save_mission(
        pm.create_mission("shop.com", "m", allowed_actions=["headers_check"]))["id"]
    out = EngagementsTabMixin._do_link_engagement(saved["payload"], "mission", mid)
    assert "error" not in out
    payload = EngagementStore().get_engagement(saved["id"])["payload"]
    assert mid in payload["linked_mission_ids"]
    # dangling reference rejected
    bad = EngagementsTabMixin._do_link_engagement(saved["payload"], "mission", "ghost")
    assert "error" in bad


def test_do_create_engagement_persists_and_validates(qapp):
    out = EngagementsTabMixin._do_create_engagement(
        "Acme", "newshop.io", {"allowed_domains": ["newshop.io"]},
        {"active_scan_enabled": False, "passive_only": True, "rate_limit": None},
        {"accepted": True, "authorized_by": "CISO"})
    assert "error" not in out and out["project"] == "newshop.io"
    assert len(EngagementStore().list_engagements("newshop.io")) == 1

    bad = EngagementsTabMixin._do_create_engagement(
        "Acme", "shop.com", {},
        {"active_scan_enabled": True, "passive_only": True}, {})
    assert "error" in bad                         # invalid ROE


def test_render_engagement_report_formats(qapp):
    saved = _save("Acme Corp", "shop.com", authorization={"accepted": True})
    md = EngagementsTabMixin._render_engagement_report(saved["payload"], "md")
    assert md.startswith("# Engagement Report ")
    html = EngagementsTabMixin._render_engagement_report(saved["payload"], "html")
    assert "<html>" in html


def test_render_retest_and_csv_helpers(qapp):
    saved = _save("Acme Corp", "shop.com")
    retest_md = EngagementsTabMixin._render_engagement_retest(saved["payload"])
    assert retest_md.startswith("# Engagement Retest ")
    csv_text = EngagementsTabMixin._engagements_csv_text("shop.com")
    assert csv_text.splitlines()[0].startswith("Engagement ID,Client")
    assert saved["id"] in csv_text
