"""gui/attack_graph_view.py
Lightweight interactive attack-path graph.

Renders one ranked attack-path record (a ``core.intelligence.build_attack_paths``
entry) as a layered node-edge diagram — **Entry (вход) → Pivot (транзит) →
Targets (цель)** — in a ``QGraphicsView`` / ``QGraphicsScene``. The layout is a
deterministic three-column layering (no third-party graph library): the entry
foothold on the left, the shared-infra pivot in the middle, the co-located
targets on the right, edges drawn entry→pivot and pivot→each target. Critical
targets and the entry severity are coloured from the shared theme palette.

Nodes are clickable: a click emits :data:`node_clicked` (node id + role) so the
hosting tab can show that node's detail. Pure presentation — it reads an
already-loaded record and never touches the data layer. Headless-safe (works
under the offscreen Qt platform used in tests).
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from qtpy.QtCore import QRectF, Qt, Signal
from qtpy.QtGui import QBrush, QColor, QFont, QPen
from qtpy.QtWidgets import (
    QGraphicsEllipseItem, QGraphicsScene, QGraphicsSimpleTextItem, QGraphicsView,
)

from gui import theme

logger = logging.getLogger(__name__)

# Cap rendered targets so a huge blast radius can't build an unbounded scene; the
# overflow collapses into a single "+N more" node.
MAX_TARGETS = 12

_NODE_W = 168.0
_NODE_H = 40.0
_COL_GAP = 130.0          # horizontal gap between layers
_ROW_GAP = 14.0           # vertical gap between stacked target nodes

# Role → fallback node colour when no severity/criticality signal applies.
_ROLE_COLOR = {
    'entry': '#c0392b',   # foothold — red-ish (overridden by entry severity)
    'pivot': '#2980b9',   # shared-infra pivot — blue
    'target': '#7f8c8d',  # co-located asset — neutral grey
    'overflow': '#566573',
}
_DATA_ID = 0
_DATA_ROLE = 1


class AttackGraphView(QGraphicsView):
    """Interactive layered graph for a single attack path.

    Emits :data:`node_clicked` ``(node_id, role)`` when a node is clicked.
    Call :meth:`render_path` with a path record to (re)draw; :meth:`clear_graph`
    to empty it.
    """

    node_clicked = Signal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(self.renderHints())   # keep default hints
        self.setMinimumHeight(220)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        # node id -> role, for selection mapping + tests
        self._node_roles: Dict[str, str] = {}

    # ── public API ────────────────────────────────────────────────────────────
    def clear_graph(self) -> None:
        self._scene.clear()
        self._node_roles = {}

    def node_roles(self) -> Dict[str, str]:
        """Mapping of rendered node id → role (entry/pivot/target/overflow)."""
        return dict(self._node_roles)

    def node_count(self) -> int:
        return len(self._node_roles)

    def render_path(self, path: Optional[Dict]) -> None:
        """Draw one attack-path record as a layered Entry → Pivot → Targets graph.

        A falsy/empty record clears the canvas. Never raises — a malformed record
        is logged and rendered as far as it can be."""
        self.clear_graph()
        if not isinstance(path, dict) or not path:
            return
        try:
            self._render(path)
        except Exception:   # noqa: BLE001 — a view must never crash the tab
            logger.exception("attack graph render failed")

    # ── rendering ───────────────────────────────────────────────────────────--
    def _render(self, path: Dict) -> None:
        entry = str(path.get('entry') or '').strip() or '—'
        entry_sev = str(path.get('entry_severity') or '').lower()
        pivot_type = str(path.get('pivot_type') or '').strip()
        pivot_node = str(path.get('pivot_node') or '').strip()
        pivot_label = (f"{pivot_type}: {pivot_node}".strip(': ')
                       or 'shared infra')
        targets: List[str] = [str(t) for t in (path.get('targets') or []) if t]
        critical = {str(path.get('goal') or '')}    # the ranked goal, if present

        col_x = [0.0, _NODE_W + _COL_GAP, 2 * (_NODE_W + _COL_GAP)]

        # Entry (left layer) — coloured by its finding severity.
        entry_color = theme.severity_color(entry_sev) or _ROLE_COLOR['entry']
        shown = targets[:MAX_TARGETS]
        stack_h = max(1, len(shown)) * (_NODE_H + _ROW_GAP)
        mid_y = stack_h / 2 - _NODE_H / 2

        self._add_node(entry, 'entry', col_x[0], mid_y, entry_color,
                       caption=f"Вход · {entry_sev or 'severity?'}")
        self._add_node(pivot_node or pivot_label, 'pivot', col_x[1], mid_y,
                       _ROLE_COLOR['pivot'], caption=f"Транзит · {pivot_label}")
        self._add_edge(col_x[0], mid_y, col_x[1], mid_y)

        # Targets (right layer), stacked; critical goal stands out.
        for i, tgt in enumerate(shown):
            y = i * (_NODE_H + _ROW_GAP)
            is_critical = tgt in critical or (i == 0 and path.get('critical_targets'))
            color = theme.severity_color('high') if is_critical \
                else _ROLE_COLOR['target']
            self._add_node(tgt, 'target', col_x[2], y, color,
                           caption="Цель" + (" · critical" if is_critical else ""))
            self._add_edge(col_x[1], mid_y, col_x[2], y)

        overflow = len(targets) - len(shown)
        if overflow > 0:
            y = len(shown) * (_NODE_H + _ROW_GAP)
            self._add_node(f"+{overflow} more", 'overflow', col_x[2], y,
                           _ROLE_COLOR['overflow'], caption="ещё цели")
            self._add_edge(col_x[1], mid_y, col_x[2], y)

        self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(
            -20, -30, 20, 30))

    def _add_node(self, node_id: str, role: str, x: float, y: float,
                  color: str, caption: str = '') -> None:
        if not node_id:
            return
        rect = QGraphicsEllipseItem(QRectF(x, y, _NODE_W, _NODE_H))
        rect.setBrush(QBrush(QColor(color)))
        rect.setPen(QPen(QColor('#1b1b1b'), 1.5))
        rect.setData(_DATA_ID, node_id)
        rect.setData(_DATA_ROLE, role)
        rect.setToolTip(f"{caption}\n{node_id}" if caption else node_id)
        rect.setCursor(Qt.PointingHandCursor)
        self._scene.addItem(rect)

        label = self._elide(node_id, 22)
        text = QGraphicsSimpleTextItem(label, rect)
        text.setBrush(QBrush(QColor('#ffffff')))
        text.setFont(QFont('Segoe UI', 8))
        tb = text.boundingRect()
        text.setPos(x + (_NODE_W - tb.width()) / 2, y + (_NODE_H - tb.height()) / 2)

        self._node_roles[node_id] = role

    def _add_edge(self, x1: float, y1: float, x2: float, y2: float) -> None:
        # connect the right edge of the source node to the left edge of the target
        self._scene.addLine(x1 + _NODE_W, y1 + _NODE_H / 2, x2, y2 + _NODE_H / 2,
                            QPen(QColor('#888'), 1.5))

    @staticmethod
    def _elide(text: str, limit: int) -> str:
        return text if len(text) <= limit else text[:limit - 1] + '…'

    # ── interaction ─────────────────────────────────────────────────────────--
    def mousePressEvent(self, event):
        node = self._node_at(event.pos())
        if node is not None:
            self.node_clicked.emit(node[0], node[1])
        super().mousePressEvent(event)

    def _node_at(self, view_pos):
        """The (node_id, role) of the node under a view position, or None."""
        for item in self.items(view_pos):
            node_id = item.data(_DATA_ID)
            if node_id:
                return str(node_id), str(item.data(_DATA_ROLE) or '')
        return None
