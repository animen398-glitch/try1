"""core/engagement_overview.py + report_export.engagements_csv (offline)."""

import csv
import io

from core import engagement as eng
from core import engagement_overview as eo
from core import report_export as rx
from core.engagement_store import EngagementStore


def _save(client, project, **kw):
    return EngagementStore().save_engagement(
        eng.create_engagement(client, project, **kw))


def test_overview_counts_and_rows():
    _save("Acme", "a.io", authorization={"accepted": True})
    auth = _save("Beta", "b.io", authorization={"accepted": True})
    EngagementStore().save_engagement(
        eng.advance_engagement_status(auth["payload"], "authorized"))

    out = eo.build_engagement_overview()
    assert out["total"] == 2
    assert out["counts"]["draft"] == 1 and out["counts"]["authorized"] == 1
    clients = {r["client"] for r in out["engagements"]}
    assert clients == {"Acme", "Beta"}


def test_overview_scoped_to_project():
    _save("Acme", "a.io")
    _save("Beta", "b.io")
    out = eo.build_engagement_overview(project="a.io")
    assert out["total"] == 1 and out["engagements"][0]["project"] == "a.io"


def test_engagements_csv_from_overview_and_bare_list():
    e = _save("Acme", "shop.io")
    table = list(csv.reader(io.StringIO(
        rx.engagements_csv(eo.build_engagement_overview()))))
    assert table[0][0] == "Engagement ID" and "Client" in table[0]
    assert any(e["id"] in row for row in table[1:])
    # bare list also accepted
    bare = list(csv.reader(io.StringIO(
        rx.engagements_csv([{"engagement_id": "eng-x", "client": "Y"}]))))
    assert bare[1][bare[0].index("Client")] == "Y"


def test_engagements_csv_empty():
    assert list(csv.reader(io.StringIO(
        rx.engagements_csv({"engagements": []}))))[0][0] == "Engagement ID"
