# pylint:disable=no-self-use
from PySide6.QtCore import QMargins, QRect, QSize, Qt
from PySide6.QtGui import QPainter
from PySide6.QtWidgets import QDockWidget, QFrame, QHBoxLayout, QStyle, QStyleOptionToolBar, QWidget


class ToolBarHandle(QWidget):
    """
    Paints a tool bar handle.
    """

    def __init__(self, *vargs, **kwargs):
        super().__init__(*vargs, **kwargs)
        self.orientation = False

    def paintEvent(self, _):
        painter = QPainter(self)
        painter.setBrush(self.palette().window())
        r = QRect(0, 0, self.width(), self.height()).marginsAdded(QMargins(1, 1, 1, 1))
        painter.drawRect(r)
        opt = QStyleOptionToolBar()
        style = self.style()
        if self.orientation:
            opt.state = QStyle.State_Horizontal
        opt.features = QStyleOptionToolBar.Movable
        opt.toolBarArea = Qt.NoToolBarArea
        opt.rect = r
        style.drawPrimitive(QStyle.PE_IndicatorToolBarHandle, opt, painter, self)
        painter.end()

    def sizeHint(self):
        return QSize(15, 15)


class CustomToolBar(QFrame):
    """
    Widget to contain the tool bar handle and main widget.
    """

    def __init__(self, widget, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setWidget(widget)

    def setWidget(self, widget):
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

    def __init__(self, widget, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.toolbar = CustomToolBar(widget)
        self.setWidget(self.toolbar)
        self.setTitleBarWidget(self.toolbar.handle)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        horizontal = self.width() > self.height()
        if horizontal:
            self.setFeatures(self.features() | QDockWidget.DockWidgetFeature.DockWidgetVerticalTitleBar)
        else:
            self.setFeatures(self.features() & ~QDockWidget.DockWidgetFeature.DockWidgetVerticalTitleBar)
        self.toolbar.handle.orientation = horizontal
