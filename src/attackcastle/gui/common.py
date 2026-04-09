from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterable

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QPoint, QRect, QSize, Qt, QTimer
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QAbstractScrollArea,
    QApplication,
    QDialog,
    QFrame,
    QHeaderView,
    QLabel,
    QLayout,
    QSizePolicy,
    QSplitter,
    QStyle,
    QStyleOption,
    QTableView,
    QVBoxLayout,
    QWidget,
    QWidgetItem,
)

from attackcastle.gui.extensions import DEFAULT_THEME_TOKENS, build_theme_stylesheet, theme_semantic_maps
from attackcastle.gui.models import FindingState

APP_LOGO_PATH = Path(__file__).resolve().parents[1] / "assets" / "logo.png"

FINDING_STATUSES = ["needs-validation", "confirmed", "duplicate", "suppressed"]
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
RUN_STATE_ORDER = {
    "running": 0,
    "failed": 1,
    "blocked": 2,
    "paused": 3,
    "completed": 4,
    "cancelled": 5,
}
_DEFAULT_SEMANTIC_MAPS = theme_semantic_maps(DEFAULT_THEME_TOKENS)
STATE_COLORS = dict(_DEFAULT_SEMANTIC_MAPS["run_states"])
SEVERITY_COLORS = dict(_DEFAULT_SEMANTIC_MAPS["severity"])
WORKFLOW_COLORS = dict(_DEFAULT_SEMANTIC_MAPS["workflow"])
CHANGE_COLORS = dict(_DEFAULT_SEMANTIC_MAPS["change"])
TOOL_STATUS_COLORS = dict(_DEFAULT_SEMANTIC_MAPS["tool_status"])


def apply_theme_semantic_maps(tokens: dict[str, Any] | None = None) -> None:
    semantic = theme_semantic_maps(tokens)
    STATE_COLORS.clear()
    STATE_COLORS.update(semantic["run_states"])
    SEVERITY_COLORS.clear()
    SEVERITY_COLORS.update(semantic["severity"])
    WORKFLOW_COLORS.clear()
    WORKFLOW_COLORS.update(semantic["workflow"])
    CHANGE_COLORS.clear()
    CHANGE_COLORS.update(semantic["change"])
    TOOL_STATUS_COLORS.clear()
    TOOL_STATUS_COLORS.update(semantic["tool_status"])


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "--"
    total = max(int(seconds), 0)
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def title_case_label(value: str) -> str:
    normalized = value.replace("_", " ").replace("-", " ").strip()
    return normalized.title() if normalized else "--"


def refresh_widget_style(widget: QWidget) -> None:
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    widget.update()


def set_tooltip(widget: QWidget, text: str) -> None:
    message = str(text or "").strip()
    if not message:
        return
    widget.setToolTip(message)
    widget.setStatusTip(message)
    widget.setWhatsThis(message)
    if isinstance(widget, QAbstractScrollArea):
        widget.viewport().setToolTip(message)


def set_tooltips(entries: Iterable[tuple[QWidget, str]]) -> None:
    for widget, text in entries:
        set_tooltip(widget, text)


def semantic_colors(value: str, palette: dict[str, tuple[str, str]]) -> tuple[str, str] | None:
    return palette.get(str(value or "").strip().lower())


def is_previewable_image(path: str) -> bool:
    suffix = Path(path).suffix.lower()
    return suffix in {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}


def format_progress(completed: int, total: int) -> str:
    if total <= 0:
        return "Waiting for plan"
    return f"{min(completed, total)}/{total} tasks complete"


def progress_percent(completed: int, total: int) -> int:
    if total <= 0:
        return 0
    return max(0, min(int((completed / total) * 100), 100))


def finding_metrics(
    findings: list[dict[str, Any]],
    finding_states: dict[str, FindingState] | None = None,
) -> dict[str, int]:
    states = finding_states or {}
    critical_high = 0
    report_ready = 0
    confirmed = 0
    for finding in findings:
        finding_id = str(finding.get("finding_id") or "")
        state = states.get(finding_id)
        severity = str(
            state.severity_override if state and state.severity_override else finding.get("severity") or "info"
        ).lower()
        if severity in {"critical", "high"}:
            critical_high += 1
        if state is None or state.include_in_report:
            report_ready += 1
        if state and state.status == "confirmed":
            confirmed += 1
    return {
        "critical_high": critical_high,
        "report_ready": report_ready,
        "confirmed": confirmed,
    }


def summarize_target_input(target_input: str) -> str:
    targets = [line.strip() for line in target_input.splitlines() if line.strip()]
    if not targets:
        return "No targets"
    if len(targets) == 1:
        return targets[0]
    return f"{targets[0]} +{len(targets) - 1} more"


def ensure_table_defaults(table: QTableView) -> None:
    table.setSelectionBehavior(QTableView.SelectRows)
    table.setSelectionMode(QTableView.SingleSelection)
    table.setAlternatingRowColors(True)
    table.setSortingEnabled(True)
    table.setWordWrap(False)
    table.verticalHeader().setVisible(False)
    header = table.horizontalHeader()
    header.setStretchLastSection(False)
    header.setMinimumSectionSize(110)
    header.setDefaultSectionSize(160)
    configure_scroll_surface(table)
    _install_table_autosizing(table)


def _install_table_autosizing(table: QTableView) -> None:
    model = table.model()
    if model is None or table.property("_autosize_bound"):
        return

    def queue_resize(*_args: object) -> None:
        if table.property("_autosize_pending"):
            return
        table.setProperty("_autosize_pending", True)

        def run_resize() -> None:
            table.setProperty("_autosize_pending", False)
            try:
                _autosize_table_columns(table)
            except RuntimeError:
                return

        QTimer.singleShot(0, run_resize)

    model.modelReset.connect(queue_resize)
    model.layoutChanged.connect(queue_resize)
    model.rowsInserted.connect(queue_resize)
    model.columnsInserted.connect(queue_resize)
    model.dataChanged.connect(queue_resize)
    table.setProperty("_autosize_bound", True)
    queue_resize()


def _autosize_table_columns(table: QTableView) -> None:
    try:
        model = table.model()
    except RuntimeError:
        return
    if model is None:
        return
    column_count = model.columnCount()
    if column_count <= 0:
        return
    try:
        header = table.horizontalHeader()
        for column in range(column_count - 1):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(column_count - 1, QHeaderView.Stretch)
        table.resizeColumnsToContents()
    except RuntimeError:
        return


class FlowLayout(QLayout):
    def __init__(self, parent: QWidget | None = None, margin: int = 0, h_spacing: int = 8, v_spacing: int = 8) -> None:
        super().__init__(parent)
        self._items: list[QLayout] = []
        self._h_spacing = h_spacing
        self._v_spacing = v_spacing
        self.setContentsMargins(margin, margin, margin, margin)

    def addItem(self, item: QWidgetItem) -> None:
        self._items.append(item)

    def addWidget(self, widget: QWidget) -> None:
        super().addWidget(widget)

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int) -> QWidgetItem | None:
        if 0 <= index < len(self._items):
            item = self._items[index]
            return item if isinstance(item, QWidgetItem) else None
        return None

    def takeAt(self, index: int) -> QWidgetItem | None:
        if 0 <= index < len(self._items):
            item = self._items.pop(index)
            return item if isinstance(item, QWidgetItem) else None
        return None

    def expandingDirections(self) -> Qt.Orientations:
        return Qt.Orientation(0)

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        return self._do_layout(QRect(0, 0, width, 0), test_only=True)

    def setGeometry(self, rect: QRect) -> None:
        super().setGeometry(rect)
        self._do_layout(rect, test_only=False)

    def sizeHint(self) -> QSize:
        return self.minimumSize()

    def minimumSize(self) -> QSize:
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        size += QSize(margins.left() + margins.right(), margins.top() + margins.bottom())
        return size

    def horizontalSpacing(self) -> int:
        if self._h_spacing >= 0:
            return self._h_spacing
        return self._smart_spacing(QStyle.PM_LayoutHorizontalSpacing)

    def verticalSpacing(self) -> int:
        if self._v_spacing >= 0:
            return self._v_spacing
        return self._smart_spacing(QStyle.PM_LayoutVerticalSpacing)

    def _do_layout(self, rect: QRect, test_only: bool) -> int:
        margins = self.contentsMargins()
        effective_rect = rect.adjusted(margins.left(), margins.top(), -margins.right(), -margins.bottom())
        x = effective_rect.x()
        y = effective_rect.y()
        line_height = 0
        spacing_x = self.horizontalSpacing()
        spacing_y = self.verticalSpacing()

        for item in self._items:
            hint = item.sizeHint()
            next_x = x + hint.width() + spacing_x
            if line_height > 0 and next_x - spacing_x > effective_rect.right() and effective_rect.width() > 0:
                x = effective_rect.x()
                y = y + line_height + spacing_y
                next_x = x + hint.width() + spacing_x
                line_height = 0
            if not test_only:
                item.setGeometry(QRect(QPoint(x, y), hint))
            x = next_x
            line_height = max(line_height, hint.height())

        return y + line_height - rect.y() + margins.bottom()

    def _smart_spacing(self, pixel_metric: QStyle.PixelMetric) -> int:
        parent = self.parent()
        if parent is None:
            return -1
        if isinstance(parent, QWidget):
            option = QStyleOption()
            option.initFrom(parent)
            return parent.style().pixelMetric(pixel_metric, option, parent)
        return parent.spacing() if hasattr(parent, "spacing") else -1


class FlowButtonRow(QWidget):
    def __init__(self, parent: QWidget | None = None, *, margin: int = 0, h_spacing: int = 8, v_spacing: int = 8) -> None:
        super().__init__(parent)
        self.setObjectName("flowButtonRow")
        self._layout = FlowLayout(self, margin=margin, h_spacing=h_spacing, v_spacing=v_spacing)
        self.setLayout(self._layout)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

    def addWidget(self, widget: QWidget) -> None:
        if isinstance(widget, QAbstractButton):
            widget.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
        self._layout.addWidget(widget)


def configure_scroll_surface(widget: QWidget) -> QWidget:
    widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
    widget.setFocusPolicy(Qt.StrongFocus)
    if isinstance(widget, QAbstractItemView):
        widget.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        widget.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
    elif isinstance(widget, QAbstractScrollArea):
        widget.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        widget.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        widget.setSizeAdjustPolicy(QAbstractScrollArea.AdjustIgnored)
        widget.viewport().setAutoFillBackground(False)
    return widget


def splitter_orientation_key(splitter: QSplitter) -> str:
    return "horizontal" if splitter.orientation() == Qt.Horizontal else "vertical"


def normalize_splitter_sizes(raw: Any, count: int) -> list[int] | None:
    if not isinstance(raw, (list, tuple)) or len(raw) != count:
        return None
    normalized: list[int] = []
    for value in raw:
        if not isinstance(value, (int, float)):
            return None
        normalized.append(max(int(value), 0))
    if not any(size > 0 for size in normalized):
        return None
    return normalized


class PersistentSplitterController(QObject):
    def __init__(
        self,
        splitter: QSplitter,
        layout_key: str,
        load_sizes: Callable[[str, str], list[int] | None] | None = None,
        save_sizes: Callable[[str, str, list[int]], None] | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.splitter = splitter
        self.layout_key = layout_key
        self._load_sizes = load_sizes
        self._save_sizes = save_sizes
        self._last_orientation = ""
        self._seeded_orientations: set[str] = set()
        self._applying = False
        self._pending_sizes: list[int] | None = None
        self._last_nonzero_sizes: dict[str, list[int]] = {}
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(160)
        self._save_timer.timeout.connect(self._flush_save)
        self.splitter.splitterMoved.connect(self._schedule_save)

    def apply(self, fallback_sizes: list[int] | None = None, *, force: bool = False) -> None:
        orientation = splitter_orientation_key(self.splitter)
        count = self.splitter.count()
        saved = normalize_splitter_sizes(self._load_sizes(self.layout_key, orientation), count) if self._load_sizes else None
        fallback = normalize_splitter_sizes(fallback_sizes, count)
        needs_seed = force or orientation != self._last_orientation or orientation not in self._seeded_orientations
        chosen = saved if saved is not None else fallback
        if chosen is None:
            self._last_orientation = orientation
            return
        if needs_seed or saved is not None:
            self._set_sizes(chosen)
            self._seeded_orientations.add(orientation)
        self._last_orientation = orientation

    def saved_or_current_sizes(self, fallback_sizes: list[int] | None = None) -> list[int] | None:
        orientation = splitter_orientation_key(self.splitter)
        count = self.splitter.count()
        if self._load_sizes is not None:
            saved = normalize_splitter_sizes(self._load_sizes(self.layout_key, orientation), count)
            if saved is not None:
                return saved
        remembered = normalize_splitter_sizes(self._last_nonzero_sizes.get(orientation), count)
        if remembered is not None:
            return remembered
        current = normalize_splitter_sizes(self.splitter.sizes(), count)
        if current is not None and any(current):
            return current
        return normalize_splitter_sizes(fallback_sizes, count)

    def _set_sizes(self, sizes: list[int]) -> None:
        self._applying = True
        try:
            self.splitter.setSizes(sizes)
        finally:
            self._applying = False
        orientation = splitter_orientation_key(self.splitter)
        if any(size > 0 for size in sizes):
            self._last_nonzero_sizes[orientation] = list(sizes)

    def _schedule_save(self, _pos: int, _index: int) -> None:
        if self._applying:
            return
        sizes = normalize_splitter_sizes(self.splitter.sizes(), self.splitter.count())
        if sizes is None:
            return
        orientation = splitter_orientation_key(self.splitter)
        if any(size > 0 for size in sizes):
            self._last_nonzero_sizes[orientation] = list(sizes)
        self._pending_sizes = list(sizes)
        self._seeded_orientations.add(orientation)
        self._last_orientation = orientation
        if self._save_sizes is not None:
            self._save_timer.start()

    def _flush_save(self) -> None:
        if self._save_sizes is None or self._pending_sizes is None:
            return
        self._save_sizes(self.layout_key, splitter_orientation_key(self.splitter), list(self._pending_sizes))


def apply_responsive_splitter(
    splitter: QSplitter,
    stretches: tuple[int, ...],
    *,
    handle_width: int = 8,
    children_collapsible: bool = True,
) -> QSplitter:
    splitter.setOpaqueResize(False)
    splitter.setChildrenCollapsible(children_collapsible)
    splitter.setHandleWidth(handle_width)
    for index, stretch in enumerate(stretches):
        splitter.setStretchFactor(index, stretch)
    return splitter


def size_dialog_to_screen(
    dialog: QDialog,
    *,
    default_width: int,
    default_height: int,
    width_ratio: float = 0.92,
    height_ratio: float = 0.9,
    min_width: int = 560,
    min_height: int = 480,
) -> None:
    screen = dialog.screen() or QApplication.primaryScreen()
    geometry = screen.availableGeometry() if screen is not None else QRect()
    if geometry.isNull():
        dialog.resize(default_width, default_height)
        return
    width = max(min_width, min(default_width, int(geometry.width() * width_ratio)))
    height = max(min_height, min(default_height, int(geometry.height() * height_ratio)))
    dialog.resize(width, height)


class SummaryCard(QFrame):
    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("summaryCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 16)
        layout.setSpacing(8)
        accent = QFrame()
        accent.setObjectName("summaryCardAccent")
        accent.setFixedHeight(3)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("summaryCardTitle")
        self.value_label = QLabel("0")
        self.value_label.setObjectName("summaryCardValue")
        self.hint_label = QLabel("")
        self.hint_label.setObjectName("summaryCardHint")
        self.hint_label.setWordWrap(True)
        layout.addWidget(accent)
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.hint_label)

    def set_value(self, value: str, hint: str = "") -> None:
        self.value_label.setText(value)
        self.hint_label.setText(hint)


class MappingTableModel(QAbstractTableModel):
    def __init__(
        self,
        columns: list[tuple[str, Callable[[dict[str, Any]], Any] | str]],
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._columns = columns
        self._rows: list[dict[str, Any]] = []

    def set_rows(self, rows: list[dict[str, Any]]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        if parent.isValid():
            return 0
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        if parent.isValid():
            return 0
        return len(self._columns)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:  # noqa: N802
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal and 0 <= section < len(self._columns):
            return self._columns[section][0]
        return section + 1

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self._rows)):
            return None
        row = self._rows[index.row()]
        column_name, accessor = self._columns[index.column()]
        value = accessor(row) if callable(accessor) else row.get(accessor)
        if role == Qt.DisplayRole:
            if value is None:
                return ""
            return str(value)
        if role == Qt.UserRole:
            return row
        if role == Qt.BackgroundRole:
            colors: tuple[str, str] | None = None
            if "scan_name" in row and "state" in row:
                colors = semantic_colors(str(row.get("state") or ""), STATE_COLORS)
            elif "effective_severity" in row:
                colors = semantic_colors(str(row.get("effective_severity") or ""), SEVERITY_COLORS)
            elif "tool_name" in row and "status" in row:
                colors = semantic_colors(str(row.get("status") or ""), TOOL_STATUS_COLORS)
            elif "change" in row and column_name == "Change":
                colors = semantic_colors(str(row.get("change") or ""), CHANGE_COLORS)
            if colors is not None:
                return QBrush(QColor(colors[0]))
        if role == Qt.ForegroundRole:
            colors = None
            normalized_column = column_name.strip().lower()
            if normalized_column == "severity" and "effective_severity" in row:
                colors = semantic_colors(str(row.get("effective_severity") or ""), SEVERITY_COLORS)
            elif normalized_column == "workflow" and "workflow_status" in row:
                colors = semantic_colors(str(row.get("workflow_status") or ""), WORKFLOW_COLORS)
            elif normalized_column == "state" and "state" in row:
                colors = semantic_colors(str(row.get("state") or ""), STATE_COLORS)
            elif normalized_column == "status" and "status" in row:
                colors = semantic_colors(str(row.get("status") or ""), TOOL_STATUS_COLORS)
            elif normalized_column == "change" and "change" in row:
                colors = semantic_colors(str(row.get("change") or ""), CHANGE_COLORS)
            if colors is not None:
                return QBrush(QColor(colors[1]))
        return None


def build_workstation_stylesheet(tokens: dict[str, Any] | None = None, qss_append: str = "") -> str:
    apply_theme_semantic_maps(tokens)
    return build_theme_stylesheet(tokens=tokens, qss_append=qss_append)
