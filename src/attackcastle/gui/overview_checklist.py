from __future__ import annotations

from typing import Any

from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from attackcastle.gui.common import (
    PANEL_CONTENT_PADDING,
    TOOLBAR_SPACING,
    configure_scroll_surface,
    refresh_widget_style,
)
from attackcastle.gui.models import OverviewChecklistItem

CHECKLIST_LIST_MIN_HEIGHT = 228
CHECKLIST_LIST_PADDING = 7
CHECKLIST_ITEM_SPACING = 5


class OverviewChecklistComposer(QFrame):
    add_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("overviewChecklistComposer")
        self.setProperty("focusWithin", False)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING)
        layout.setSpacing(TOOLBAR_SPACING)

        self.input = QLineEdit()
        self.input.setObjectName("overviewChecklistInput")
        self.input.setPlaceholderText("Add validation step, retest task, or note")
        self.input.returnPressed.connect(self._emit_add_requested)
        self.input.installEventFilter(self)

        self.add_button = QPushButton("Add")
        self.add_button.setObjectName("overviewChecklistAddButton")
        self.add_button.setCursor(Qt.PointingHandCursor)
        self.add_button.setMinimumWidth(72)
        self.add_button.clicked.connect(self._emit_add_requested)
        self.add_button.installEventFilter(self)

        layout.addWidget(self.input, 1)
        layout.addWidget(self.add_button, 0, Qt.AlignVCenter)

    def clear(self) -> None:
        self.input.clear()

    def focus_input(self) -> None:
        self.input.setFocus(Qt.OtherFocusReason)

    def eventFilter(self, watched: QObject | None, event: QEvent) -> bool:
        if watched in {self.input, self.add_button} and event.type() in {QEvent.FocusIn, QEvent.FocusOut}:
            QTimer.singleShot(0, self._sync_focus_state)
        return super().eventFilter(watched, event)

    def _emit_add_requested(self) -> None:
        self.add_requested.emit(self.input.text().strip())

    def _sync_focus_state(self) -> None:
        has_focus = self.input.hasFocus() or self.add_button.hasFocus()
        if has_focus == bool(self.property("focusWithin")):
            return
        self.setProperty("focusWithin", has_focus)
        refresh_widget_style(self)


class OverviewChecklistItemCard(QFrame):
    toggled = Signal(str)
    delete_requested = Signal(str)

    def __init__(self, item: OverviewChecklistItem, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.item_id = item.item_id
        self.setObjectName("overviewChecklistItemCard")
        self.setCursor(Qt.PointingHandCursor)
        self.setAttribute(Qt.WA_Hover, True)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING)
        layout.setSpacing(TOOLBAR_SPACING)

        self.toggle_box = QCheckBox()
        self.toggle_box.setObjectName("overviewChecklistToggle")
        self.toggle_box.setCursor(Qt.PointingHandCursor)
        self.toggle_box.clicked.connect(lambda _checked=False: self.toggled.emit(self.item_id))

        self.label = QLabel()
        self.label.setObjectName("overviewChecklistItemLabel")
        self.label.setWordWrap(True)
        self.label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        self.delete_button = QPushButton("x")
        self.delete_button.setObjectName("overviewChecklistDelete")
        self.delete_button.setCursor(Qt.PointingHandCursor)
        self.delete_button.setToolTip("Delete checklist item")
        self.delete_button.setFixedSize(24, 24)
        self.delete_button.setVisible(False)
        self.delete_button.clicked.connect(lambda _checked=False: self.delete_requested.emit(self.item_id))

        layout.addWidget(self.toggle_box, 0, Qt.AlignTop)
        layout.addWidget(self.label, 1)
        layout.addWidget(self.delete_button, 0, Qt.AlignTop)
        self.set_item(item)

    def set_item(self, item: OverviewChecklistItem) -> None:
        self.item_id = item.item_id
        self.label.setText(item.label)
        self.setProperty("completed", item.completed)
        self.label.setProperty("completed", item.completed)

        self.toggle_box.blockSignals(True)
        self.toggle_box.setChecked(item.completed)
        self.toggle_box.blockSignals(False)

        refresh_widget_style(self)
        refresh_widget_style(self.label)
        refresh_widget_style(self.toggle_box)

    def enterEvent(self, event: Any) -> None:  # noqa: N802
        self.delete_button.setVisible(True)
        super().enterEvent(event)

    def leaveEvent(self, event: Any) -> None:  # noqa: N802
        self.delete_button.setVisible(False)
        super().leaveEvent(event)

    def mousePressEvent(self, event: Any) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton:
            point = event.position().toPoint() if hasattr(event, "position") else event.pos()
            child = self.childAt(point)
            if child not in {self.delete_button, self.toggle_box}:
                self.toggled.emit(self.item_id)
        super().mousePressEvent(event)


class OverviewChecklistEmptyState(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("overviewChecklistEmptyState")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING)
        layout.setSpacing(TOOLBAR_SPACING)
        layout.setAlignment(Qt.AlignCenter)

        icon = QLabel("+")
        icon.setObjectName("overviewChecklistEmptyIcon")
        icon.setAlignment(Qt.AlignCenter)

        title = QLabel("No checklist items yet")
        title.setObjectName("overviewChecklistEmptyTitle")
        title.setAlignment(Qt.AlignCenter)

        summary = QLabel("Add an item to create a checklist")
        summary.setObjectName("overviewChecklistEmptySummary")
        summary.setAlignment(Qt.AlignCenter)
        summary.setWordWrap(True)

        layout.addWidget(icon, 0, Qt.AlignHCenter)
        layout.addWidget(title)
        layout.addWidget(summary)


class OverviewChecklistPanel(QFrame):
    add_requested = Signal(str)
    toggled = Signal(str)
    delete_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("overviewChecklistPanel")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING, PANEL_CONTENT_PADDING)
        layout.setSpacing(TOOLBAR_SPACING)

        header = QWidget()
        header.setObjectName("overviewChecklistHeader")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(0)

        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(TOOLBAR_SPACING)

        self.title_label = QLabel("Checklist")
        self.title_label.setObjectName("overviewChecklistTitle")

        self.count_badge = QLabel("Ready")
        self.count_badge.setObjectName("overviewChecklistCountBadge")
        self.count_badge.setAlignment(Qt.AlignCenter)

        title_row.addWidget(self.title_label)
        title_row.addStretch(1)
        title_row.addWidget(self.count_badge, 0, Qt.AlignTop)
        header_layout.addLayout(title_row)

        self.composer = OverviewChecklistComposer()
        self.composer.add_requested.connect(self.add_requested.emit)

        self.list_surface = QFrame()
        self.list_surface.setObjectName("overviewChecklistListSurface")
        self.list_surface.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        list_surface_layout = QVBoxLayout(self.list_surface)
        list_surface_layout.setContentsMargins(1, 1, 1, 1)
        list_surface_layout.setSpacing(0)

        self.scroll_area = configure_scroll_surface(QScrollArea())
        self.scroll_area.setObjectName("overviewChecklistScroll")
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll_area.setMinimumHeight(CHECKLIST_LIST_MIN_HEIGHT)

        self.list_container = QWidget()
        self.list_container.setObjectName("overviewChecklistListContainer")
        self.list_layout = QVBoxLayout(self.list_container)
        self.list_layout.setContentsMargins(CHECKLIST_LIST_PADDING, CHECKLIST_LIST_PADDING, CHECKLIST_LIST_PADDING, CHECKLIST_LIST_PADDING)
        self.list_layout.setSpacing(CHECKLIST_ITEM_SPACING)
        self.scroll_area.setWidget(self.list_container)
        list_surface_layout.addWidget(self.scroll_area)

        self._rows: dict[str, OverviewChecklistItemCard] = {}

        layout.addWidget(header)
        layout.addWidget(self.composer)
        layout.addWidget(self.list_surface, 1)

    def clear_input(self) -> None:
        self.composer.clear()

    def focus_input(self) -> None:
        self.composer.focus_input()

    def set_items(self, items: list[OverviewChecklistItem]) -> None:
        self._rows = {}
        while self.list_layout.count():
            item = self.list_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        has_items = bool(items)
        empty_state = OverviewChecklistEmptyState()
        empty_state.setVisible(not has_items)
        self.list_layout.addWidget(empty_state)

        for item in items:
            row = OverviewChecklistItemCard(item)
            row.toggled.connect(self.toggled.emit)
            row.delete_requested.connect(self.delete_requested.emit)
            self._rows[item.item_id] = row
            self.list_layout.addWidget(row)

        self.list_layout.addStretch(1)
        self._update_count_badge(items)

    def _update_count_badge(self, items: list[OverviewChecklistItem]) -> None:
        total = len(items)
        pending = sum(0 if item.completed else 1 for item in items)
        completed = total - pending

        if total == 0:
            text = "Ready"
            tone = "ready"
        elif pending == 0:
            text = f"{completed} complete"
            tone = "complete"
        else:
            text = f"{pending} active"
            tone = "active"

        self.count_badge.setText(text)
        self.count_badge.setProperty("tone", tone)
        refresh_widget_style(self.count_badge)
