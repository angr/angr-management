# pylint:disable=no-self-use
from __future__ import annotations

from PySide6.QtCore import QMargins, QRect, QSize, Qt
from PySide6.QtGui import QPainter
from PySide6.QtWidgets import QDockWidget, QFrame, QHBoxLayout, QStyle, QStyleOptionToolBar, QWidget


class ToolBarHandle(QWidget):
    """
    Paints a tool bar handle.
    """

    def __init__(self, *vargs, **kwargs) -> None:
        super().__init__(*vargs, **kwargs)
        self.orientation = False

    def paintEvent(self, _) -> None:
        painter = QPainter(self)
        painter.setBrush(self.palette().window())
        r = QRect(0, 0, self.width(), self.height()).marginsAdded(QMargins(1, 1, 1, 1))
        painter.drawRect(r)
        opt = QStyleOptionToolBar()
        style = self.style()
        if self.orientation:
            opt.state = QStyle.StateFlag.State_Horizontal
        opt.features = QStyleOptionToolBar.ToolBarFeature.Movable
        opt.toolBarArea = Qt.ToolBarArea.NoToolBarArea
        opt.rect = r
        style.drawPrimitive(QStyle.PrimitiveElement.PE_IndicatorToolBarHandle, opt, painter, self)
        painter.end()

    def sizeHint(self):
        return QSize(15, 15)


class CustomToolBar(QFrame):
    """
    Widget to contain the tool bar handle and main widget.
    """

    def __init__(self, widget) -> None:
        super().__init__()
        self.setWidget(widget)

    def setWidget(self, widget) -> None:
        layout = QHBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.handle = ToolBarHandle(parent=self)
        layout.addWidget(self.handle)
        layout.addWidget(widget)
        self.setLayout(layout)

    def sizeHint(self):
        return QSize(25, 25)


class ToolBarDockWidget(QDockWidget):
    """
    Custom tool bar using QDockWidget for better resize handling than QToolBar for large widgets.
    """

    def __init__(self, widget, title, parent) -> None:
        super().__init__(title, parent)
        self.toolbar = CustomToolBar(widget)
        self.setWidget(self.toolbar)
        self.setTitleBarWidget(self.toolbar.handle)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        horizontal = self.width() > self.height()
        if horizontal:
            self.setFeatures(self.features() | QDockWidget.DockWidgetFeature.DockWidgetVerticalTitleBar)
        else:
            self.setFeatures(self.features() & ~QDockWidget.DockWidgetFeature.DockWidgetVerticalTitleBar)
        self.toolbar.handle.orientation = horizontal
