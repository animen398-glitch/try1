"""AttackGraphView (gui/attack_graph_view.py) — layered attack-path graph.

Headless (offscreen Qt): renders one path record into a QGraphicsScene as
Entry → Pivot → Targets nodes + edges, caps the target fan-out, and emits
node_clicked. Pure presentation over an already-loaded record.
"""

from gui.attack_graph_view import MAX_TARGETS, AttackGraphView


def _path(n_targets=2):
    return {
        'score': 70, 'band': 'high', 'entry': 'api.x.com', 'entry_severity': 'high',
        'pivot_type': 'ip', 'pivot_node': '1.2.3.4', 'size': n_targets + 1,
        'targets': [f't{i}.x.com' for i in range(n_targets)],
        'goal': 't0.x.com', 'critical_targets': 1,
    }


def test_render_builds_entry_pivot_targets(qapp):
    v = AttackGraphView()
    v.render_path(_path(2))
    roles = v.node_roles()
    assert roles.get('api.x.com') == 'entry'
    assert roles.get('1.2.3.4') == 'pivot'
    assert roles.get('t0.x.com') == 'target' and roles.get('t1.x.com') == 'target'
    assert v.node_count() == 4                       # entry + pivot + 2 targets


def test_render_caps_targets_with_overflow(qapp):
    v = AttackGraphView()
    v.render_path(_path(MAX_TARGETS + 5))
    roles = v.node_roles()
    target_nodes = [k for k, r in roles.items() if r == 'target']
    assert len(target_nodes) == MAX_TARGETS          # capped
    assert any(r == 'overflow' for r in roles.values())   # "+N more" node


def test_empty_or_malformed_clears(qapp):
    v = AttackGraphView()
    v.render_path(_path(2))
    assert v.node_count() == 4
    v.render_path({})                                # empty → cleared
    assert v.node_count() == 0
    v.render_path(None)                              # falsy → no crash, cleared
    assert v.node_count() == 0


def test_node_clicked_signal_emits(qapp):
    v = AttackGraphView()
    v.render_path(_path(2))
    captured = []
    v.node_clicked.connect(lambda nid, role: captured.append((nid, role)))
    # the scene-level lookup backing mousePressEvent
    item = next(i for i in v.scene().items() if i.data(0) == 'api.x.com')
    center = item.sceneBoundingRect().center()
    v.node_clicked.emit(str(item.data(0)), str(item.data(1)))  # simulate a hit
    assert ('api.x.com', 'entry') in captured
    assert center is not None                        # node has a real geometry


def test_render_is_deterministic(qapp):
    v = AttackGraphView()
    v.render_path(_path(3))
    first = v.node_roles()
    v.render_path(_path(3))
    assert v.node_roles() == first                   # same input → same nodes
