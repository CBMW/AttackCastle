from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from attackcastle.gui.common import (
    PAGE_CARD_SPACING,
    PAGE_SECTION_SPACING,
    PANEL_CONTENT_PADDING,
    configure_tab_widget,
    title_case_label,
)

REPORT_DONUT_COLORS = ("#000000", "#DA291C", "#ED8B00", "#86BC25", "#007CB0", "#6F7782")
SEVERITY_DONUT_COLORS = {
    "critical": REPORT_DONUT_COLORS[0],
    "high": REPORT_DONUT_COLORS[1],
    "medium": REPORT_DONUT_COLORS[2],
    "low": REPORT_DONUT_COLORS[3],
    "info": REPORT_DONUT_COLORS[4],
}
SEVERITY_LABELS = ("critical", "high", "medium", "low", "info")
DONUT_HOLE_RATIO = 0.75
DONUT_CENTER_FILL = QColor("#101010")
DONUT_CENTER_BORDER = QColor("#343434")


@dataclass(slots=True)
class GeneralOverviewData:
    total_assets: int = 0
    total_services: int = 0
    total_endpoints: int = 0
    total_findings: int = 0
    tasks_in_progress: int = 0
    tasks_completed: int = 0
    total_retested_findings: int = 0
    remediated_count: int = 0
    partial_count: int = 0
    not_remediated_count: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    root_cause_counts: dict[str, int] = field(default_factory=dict)


class DonutChartWidget(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("generalDonutChart")
        self.setMinimumSize(152, 136)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._segments: list[tuple[str, int, QColor]] = []
        self._center_title = "Severity"
        self._center_value = "0"

    def set_segments(self, segments: list[tuple[str, int, str]], *, center_title: str) -> None:
        self._segments = [
            (label, max(int(value), 0), QColor(color))
            for label, value, color in segments
            if max(int(value), 0) > 0
        ]
        self._center_title = center_title
        self._center_value = str(sum(value for _label, value, _color in self._segments))
        self.update()

    def paintEvent(self, event: Any) -> None:  # noqa: N802
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        side = int((min(self.width(), self.height()) - 24) * 0.8)
        if side <= 0:
            return
        rect = QRectF((self.width() - side) / 2, (self.height() - side) / 2, side, side)
        hole_inset = side * (1.0 - DONUT_HOLE_RATIO) / 2.0
        inner = rect.adjusted(hole_inset, hole_inset, -hole_inset, -hole_inset)

        total = sum(value for _label, value, _color in self._segments)
        if total <= 0:
            painter.setPen(QPen(QColor("#E7E0D5"), 2))
            painter.setBrush(QColor("#F6F0E6"))
            painter.drawEllipse(rect)
            painter.setPen(QPen(DONUT_CENTER_BORDER, 1))
            painter.setBrush(DONUT_CENTER_FILL)
            painter.drawEllipse(inner)
        else:
            start_angle = 0.0
            for _label, value, color in self._segments:
                span_angle = (value / total) * 360.0
                path = QPainterPath()
                path.arcMoveTo(rect, start_angle)
                path.arcTo(rect, start_angle, span_angle)
                path.arcTo(inner, start_angle + span_angle, -span_angle)
                path.closeSubpath()
                painter.setPen(QPen(QColor("#FFFFFF"), 2))
                painter.setBrush(color)
                painter.drawPath(path)
                start_angle += span_angle

            painter.setPen(QPen(DONUT_CENTER_BORDER, 1))
            painter.setBrush(DONUT_CENTER_FILL)
            painter.drawEllipse(inner)

        center = rect.center()
        title_font = QFont(self.font())
        title_font.setPointSize(max(self.font().pointSize(), 9))
        title_font.setBold(False)
        value_font = QFont(self.font())
        value_font.setPointSize(max(self.font().pointSize() + 7, 16))
        value_font.setBold(True)

        painter.setPen(QColor("#D8DEE9"))
        painter.setFont(title_font)
        painter.drawText(
            QRectF(center.x() - side * 0.25, center.y() - 23, side * 0.5, 18),
            Qt.AlignCenter,
            self._center_title,
        )
        painter.setPen(QColor("#FFFFFF"))
        painter.setFont(value_font)
        painter.drawText(
            QRectF(center.x() - side * 0.25, center.y() - 4, side * 0.5, 30),
            Qt.AlignCenter,
            self._center_value,
        )


class DonutPanel(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("generalDonutPanel")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)

        self.chart = DonutChartWidget()
        self.legend_host = QWidget()
        self.legend_host.setObjectName("generalLegendHost")
        self.legend_layout = QVBoxLayout(self.legend_host)
        self.legend_layout.setContentsMargins(0, 0, 0, 0)
        self.legend_layout.setSpacing(PAGE_CARD_SPACING)

        layout.addWidget(self.chart, 3)
        layout.addWidget(self.legend_host, 2)

    def set_segments(self, segments: list[tuple[str, int, str]], *, center_title: str) -> None:
        self.chart.set_segments(segments, center_title=center_title)
        while self.legend_layout.count():
            item = self.legend_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        visible_segments = [(label, value, color) for label, value, color in segments if value > 0]
        if not visible_segments:
            empty = QLabel("No data")
            empty.setObjectName("generalLegendEmpty")
            self.legend_layout.addWidget(empty)
        else:
            for label, value, color in visible_segments:
                self.legend_layout.addWidget(self._build_legend_row(label, value, color))
        self.legend_layout.addStretch(1)

    def _build_legend_row(self, label: str, value: int, color: str) -> QWidget:
        row = QWidget()
        row.setObjectName("generalLegendRow")
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_CARD_SPACING)

        swatch = QLabel()
        swatch.setObjectName("generalLegendSwatch")
        swatch.setProperty("swatchColor", color)
        swatch.setFixedSize(10, 10)
        swatch.setStyleSheet(f"background: {color}; border: 1px solid #FFFFFF; border-radius: 1px;")

        name = QLabel(label)
        name.setObjectName("generalLegendLabel")
        name.setWordWrap(True)
        count = QLabel(str(value))
        count.setObjectName("generalLegendValue")
        count.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        count.setMinimumWidth(30)

        layout.addWidget(swatch, 0, Qt.AlignVCenter)
        layout.addWidget(name, 1)
        layout.addWidget(count, 0)
        return row


class OverviewGeneralPanel(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("overviewGeneralPanel")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(PAGE_SECTION_SPACING)

        body = QWidget()
        body.setObjectName("overviewGeneralBody")
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(PAGE_SECTION_SPACING * 3)

        metrics = QFrame()
        metrics.setObjectName("generalMetricsPanel")
        metrics.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        metrics_layout = QVBoxLayout(metrics)
        metrics_layout.setContentsMargins(
            PANEL_CONTENT_PADDING + 7,
            PANEL_CONTENT_PADDING + 8,
            PANEL_CONTENT_PADDING + 7,
            PANEL_CONTENT_PADDING + 8,
        )
        metrics_layout.setSpacing(PAGE_CARD_SPACING + 3)
        self.metric_values: dict[str, QLabel] = {}
        metric_rows = [
            ("total_assets", "Total Assets"),
            ("total_services", "Total Services"),
            ("total_endpoints", "Total Endpoints"),
            ("total_findings", "Total Findings"),
            ("tasks_in_progress", "Tasks In Progress"),
            ("tasks_completed", "Tasks Completed"),
            ("remediated_count", "Remediated"),
            ("partial_count", "Partially Remediated"),
            ("not_remediated_count", "Not Remediated"),
        ]
        for key, label_text in metric_rows:
            row, value = self._build_metric_row(label_text)
            metrics_layout.addWidget(row)
            self.metric_values[key] = value
        metrics_layout.addStretch(1)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("generalTabs")
        configure_tab_widget(self.tabs, role="inspector")
        self.severity_panel = DonutPanel()
        self.root_cause_panel = DonutPanel()
        self.tabs.addTab(self.severity_panel, "Severity Count")
        self.tabs.addTab(self.root_cause_panel, "Root Causes")

        body_layout.addWidget(metrics, 2)
        body_layout.addWidget(self.tabs, 3)
        layout.addWidget(body, 1)

    def _build_metric_row(self, label_text: str) -> tuple[QWidget, QLabel]:
        row = QFrame()
        row.setObjectName("generalMetricRow")
        row.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout = QHBoxLayout(row)
        layout.setContentsMargins(PANEL_CONTENT_PADDING, 5, PANEL_CONTENT_PADDING, 5)
        layout.setSpacing(PAGE_SECTION_SPACING)

        label = QLabel(label_text)
        label.setObjectName("generalMetricLabel")
        label.setWordWrap(False)
        value = QLabel("0")
        value.setObjectName("generalMetricValue")
        value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        value.setMinimumWidth(48)

        layout.addWidget(label, 1)
        layout.addWidget(value, 0)
        return row, value

    def set_data(self, data: GeneralOverviewData) -> None:
        values = {
            "total_assets": data.total_assets,
            "total_services": data.total_services,
            "total_endpoints": data.total_endpoints,
            "total_findings": data.total_findings,
            "tasks_in_progress": data.tasks_in_progress,
            "tasks_completed": data.tasks_completed,
            "remediated_count": data.remediated_count,
            "partial_count": data.partial_count,
            "not_remediated_count": data.not_remediated_count,
        }
        for key, value in values.items():
            self.metric_values[key].setText(str(max(int(value), 0)))

        severity_segments = [
            (
                title_case_label(severity),
                int(data.severity_counts.get(severity, 0) or 0),
                SEVERITY_DONUT_COLORS[severity],
            )
            for severity in SEVERITY_LABELS
        ]
        self.severity_panel.set_segments(severity_segments, center_title="Findings")

        root_cause_segments: list[tuple[str, int, str]] = []
        for index, (label, count) in enumerate(
            sorted(data.root_cause_counts.items(), key=lambda item: (-int(item[1]), item[0].lower()))
        ):
            root_cause_segments.append((label, int(count), REPORT_DONUT_COLORS[index % len(REPORT_DONUT_COLORS)]))
        self.root_cause_panel.set_segments(root_cause_segments, center_title="Causes")
