"""Missions GUI tab — headless thin surface tests (Mission Center M3)."""

from core import pentest_mission as pm
from core.mission_store import MissionStore
from gui.plugin_manager import default_manager
from gui.tab_missions import MissionsTabMixin
from tests.gui_test_helpers import MissionsHost


def _seed_mission(project="shop.com", objective="Authorized external review",
                  *, status="draft", allowed_actions=("headers_check",)):
    mission = pm.create_mission(project, objective,
                                allowed_actions=list(allowed_actions))
    if status != "draft":
        mission = pm.advance_mission_status(mission, status)
    return MissionStore().save_mission(mission)


def test_tab_builds_with_columns(qapp):
    w = MissionsHost()
    assert hasattr(w, "_missions_widget")
    assert w.mission_table.columnCount() == len(MissionsTabMixin.MISSION_COLUMNS)
    assert not w.btn_mission_advance.isEnabled()
    assert not w.btn_mission_link_run.isEnabled()


def test_missions_registered_in_tab_bar(qapp):
    assert "Missions" in [p.title for p in default_manager()]


def test_query_projects_lists_mission_projects(qapp):
    _seed_mission("shop.com")
    _seed_mission("bank.example", objective="Review portal")
    out = MissionsTabMixin._query_mission_projects()
    assert "error" not in out
    assert {"shop.com", "bank.example"} <= set(out["projects"])


def test_query_missions_bundles_link_sources(qapp):
    from core.findings_adapter import Finding
    from core.findings_store import FindingsStore

    _seed_mission("shop.com")
    store = FindingsStore()
    store.upsert("shop.com", Finding(
        category="vuln", rule_id="edge", title="Exposed map",
        severity="high", location="https://shop.com/a.js.map").to_store(),
        scan_id="s1")

    out = MissionsTabMixin._query_missions("shop.com")
    assert "error" not in out
    assert len(out["missions"]) == 1
    assert len(out["findings"]) == 1          # active finding offered as a link source


def test_populate_and_select_shows_detail_and_advance_targets(qapp):
    w = MissionsHost()
    _seed_mission("shop.com", status="ready")
    w._populate_missions(MissionsTabMixin._query_missions("shop.com"))

    assert w.mission_table.rowCount() == 1
    w.mission_table.selectRow(0)

    detail = w.mission_detail.toPlainText()
    assert "Authorized external review" in detail
    # 'ready' may advance to running/draft/archived — legal targets only.
    targets = {w.mission_advance_status.itemData(i)
               for i in range(w.mission_advance_status.count())}
    assert targets == {"running", "draft", "archived"}
    assert w.btn_mission_advance.isEnabled()


def test_advance_mission_persists_new_status(qapp):
    saved = _seed_mission("shop.com", status="ready")
    out = MissionsTabMixin._do_advance_mission(saved["payload"], "running")
    assert "error" not in out
    assert MissionStore().get_mission(saved["id"])["status"] == "running"


def test_advance_illegal_transition_reports_error(qapp):
    saved = _seed_mission("shop.com", status="draft")
    out = MissionsTabMixin._do_advance_mission(saved["payload"], "completed")
    assert "error" in out
    assert MissionStore().get_mission(saved["id"])["status"] == "draft"


def test_run_button_enabled_only_for_ready_mission(qapp):
    w = MissionsHost()
    _seed_mission("shop.com", status="draft")
    w._populate_missions(MissionsTabMixin._query_missions("shop.com"))
    w.mission_table.selectRow(0)
    assert not w.btn_mission_run.isEnabled()           # draft → not runnable

    MissionStore()  # ensure store exists
    _seed_mission("shop.com", objective="Ready review", status="ready")
    w._populate_missions(MissionsTabMixin._query_missions("shop.com"))
    # select the ready one
    for i, m in enumerate(w._mission_rows):
        if m["status"] == "ready":
            w.mission_table.selectRow(i)
            break
    assert w.btn_mission_run.isEnabled()


def test_do_run_mission_executes_and_links(qapp):
    saved = _seed_mission("shop.com", status="ready")
    out = MissionsTabMixin._do_run_mission(saved["payload"])
    assert "error" not in out and "ran" in out["ok"]
    mission = MissionStore().get_mission(saved["id"])
    assert mission["status"] == "completed"
    assert len(mission["payload"]["linked_audit_run_ids"]) == 1


def test_do_create_mission_persists_client_safe_mission(qapp):
    out = MissionsTabMixin._do_create_mission(
        "newshop.io", "Authorized review", None,
        {"profile": "client_safe", "allowed_domains": ["newshop.io"]},
        ["headers_check"])
    assert "error" not in out and out["project"] == "newshop.io"
    missions = MissionStore().list_missions("newshop.io")
    assert len(missions) == 1
    assert missions[0]["payload"]["objective"] == "Authorized review"
    assert missions[0]["payload"]["allowed_actions"] == ["headers_check"]


def test_do_create_mission_rejects_non_client_safe_action(qapp):
    out = MissionsTabMixin._do_create_mission(
        "shop.com", "Bad mission", None, None, ["exploit"])
    assert "error" in out
    assert MissionStore().list_missions("shop.com") == []


def test_create_panel_builds_action_checkboxes(qapp):
    from core.audit_checks import SAFE_CHECKS
    w = MissionsHost()
    assert set(w.mission_create_actions) == set(SAFE_CHECKS)
    assert hasattr(w, "btn_mission_create")


def test_schedule_buttons_and_do_schedule(qapp):
    saved = _seed_mission("shop.com", status="ready")
    w = MissionsHost()
    w._populate_missions(MissionsTabMixin._query_missions("shop.com"))
    w.mission_table.selectRow(0)
    assert w.btn_mission_schedule.isEnabled()
    assert not w.btn_mission_unschedule.isEnabled()       # not scheduled yet
    assert w.btn_mission_run_due.isEnabled()

    out = MissionsTabMixin._do_schedule_mission(saved["id"], "daily")
    assert "error" not in out
    assert MissionStore().get_schedule(saved["id"])["interval"] == "daily"

    off = MissionsTabMixin._do_unschedule_mission(saved["id"])
    assert "error" not in off
    assert MissionStore().get_schedule(saved["id"])["enabled"] is False


def test_do_run_due_missions(qapp):
    from core import mission_schedule as ms
    saved = _seed_mission("shop.com", status="ready")
    ms.set_mission_schedule(saved["id"], "daily")
    MissionStore().set_schedule(
        saved["id"], {**MissionStore().get_schedule(saved["id"]),
                      "next_run": "2020-01-01T00:00:00"})
    out = MissionsTabMixin._do_run_due_missions()
    assert "error" not in out and "ran" in out["ok"]


def test_report_buttons_enable_on_selection_and_render(qapp):
    w = MissionsHost()
    _seed_mission("shop.com", status="ready")
    w._populate_missions(MissionsTabMixin._query_missions("shop.com"))
    assert not w.btn_mission_report_md.isEnabled()        # nothing selected yet
    w.mission_table.selectRow(0)
    assert w.btn_mission_report_json.isEnabled()
    assert w.btn_mission_report_md.isEnabled()
    assert w.btn_mission_report_html.isEnabled()

    payload = w._selected_mission()["payload"]
    md = MissionsTabMixin._render_mission_report(payload, "md")
    assert md.startswith("# Mission Report")
    assert "<html>" in MissionsTabMixin._render_mission_report(payload, "html")


def test_link_run_and_finding_persist_on_mission(qapp):
    saved = _seed_mission("shop.com")
    MissionsTabMixin._do_link_run(saved["payload"], "audit-shop")
    # the GUI refreshes between actions, so the second link starts from the
    # persisted (already-linked) payload — not the stale original.
    updated = MissionStore().get_mission(saved["id"])["payload"]
    MissionsTabMixin._do_link_finding(updated, "f-123")

    payload = MissionStore().get_mission(saved["id"])["payload"]
    assert payload["linked_audit_run_ids"] == ["audit-shop"]
    assert payload["linked_finding_ids"] == ["f-123"]
