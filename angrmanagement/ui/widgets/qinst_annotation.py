import logging

from PySide2.QtGui import QColor, QPen, QPainterPath, QBrush, QFont, QCursor
from PySide2.QtCore import QRectF, QMarginsF
from PySide2.QtWidgets import QHBoxLayout, QLabel, QWidget, QGraphicsProxyWidget, QGraphicsItem, QGraphicsWidget, \
    QGraphicsSimpleTextItem, QGraphicsItemGroup, QGraphicsLinearLayout, QGraphicsSceneMouseEvent, QMenu, \
    QGraphicsSceneMouseEvent, QInputDialog, QLineEdit

from .qsimulation_managers import QSimulationManagers
from ...logic import GlobalInfo
from ...config import Conf


class QInstructionAnnotation(QGraphicsSimpleTextItem):
    """Abstract"""

    background_color = None
    foreground_color = None
    _config = Conf

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setBrush(QBrush(self.foreground_color))
        self.setFont(self._config.disasm_font)

    def paint(self, painter, *args, **kwargs):
        margin = QMarginsF(3, 0, 3, 0)
        box = self.boundingRect().marginsAdded(margin)
        path = QPainterPath()
        path.addRoundedRect(box, 5, 5)
        painter.fillPath(path, self.background_color)
        super().paint(painter, *args, **kwargs)


class QStatsAnnotation(QInstructionAnnotation):
    """Abstract"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setAcceptHoverEvents(True)
        self.disasm_view = GlobalInfo.main_window.workspace.view_manager.first_view_in_category(
            "disassembly")  # type: DisassemblyView
        self.symexec_view = GlobalInfo.main_window.workspace.view_manager.first_view_in_category(
            "symexec")  # type: SymexecView
        self.hovered = False

    def mousePressEvent(self, event):
        pass

    def hoverEnterEvent(self, event):
        self.hovered = True
        self.disasm_view.redraw_current_graph()

    def hoverLeaveEvent(self, event):
        self.hovered = False
        self.disasm_view.redraw_current_graph()

    def paint(self, painter, *args, **kwargs):
        if self.hovered:
            margin = QMarginsF(13, 10, 13, 10)
        else:
            margin = QMarginsF(3, 0, 3, 0)
        box = self.boundingRect().marginsAdded(margin)
        path = QPainterPath()
        if self.hovered:
            path.addRoundedRect(box, 20, 20)
        else:
            path.addRoundedRect(box, 5, 5)
        painter.fillPath(path, self.background_color)
        super().paint(painter, *args, **kwargs)


class QActiveCount(QStatsAnnotation):
    background_color = QColor(0, 255, 0, 30)
    foreground_color = QColor(0, 60, 0)

    def __init__(self, states):
        super().__init__(str(len(states)))
        self.states = states

    def mouseReleaseEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        menu = QMenu()

        def _select_states():
            self.symexec_view.select_states(self.states)
            self.disasm_view.workspace.raise_view(self.symexec_view)

        def _move_states():
            to_stash = QInputDialog.getText(self.disasm_view, "Move to?", "Target Stash Name:", QLineEdit.Normal)
            if to_stash[1]:
                self.symexec_view.current_simgr.move("active", to_stash[0], lambda s: s in self.states)
                self.disasm_view.refresh()

        menu.addAction("Select", _select_states)
        menu.addAction("Move To", _move_states)
        menu.exec_(QCursor.pos())


class QPassthroughCount(QStatsAnnotation):
    background_color = QColor(255, 0, 0, 30)
    foreground_color = QColor(60, 0, 0)

    def __init__(self, addr, count):
        super().__init__(str(count))
        self.addr = addr

    def mousePressEvent(self, event):
        self.symexec_view.select_states_that_passed_through(self.addr)
        self.disasm_view.workspace.raise_view(self.symexec_view)


class QHookAnnotation(QInstructionAnnotation):
    background_color = QColor(230, 230, 230)
    foreground_color = QColor(50, 50, 50)

    def __init__(self, disasm_view, addr, *args, **kwargs):
        super().__init__("hook", *args, **kwargs)
        self.disasm_view = disasm_view
        self.addr = addr

    def contextMenuEvent(self, event):
        menu = QMenu()
        menu.addAction("Modify", self.modify)
        menu.addAction("Delete", self.delete)
        menu.exec_(QCursor.pos())

    def modify(self):
        self.disasm_view.popup_modify_hook_dialog(addr=self.addr)

    def delete(self):
        GlobalInfo.main_window.workspace.instance.delete_hook(self.addr)
        self.disasm_view.refresh()


class QExploreAnnotation(QInstructionAnnotation):
    """Abstract"""

    background_color = None
    foreground_color = QColor(230, 230, 230)
    text = None

    def __init__(self, disasm_view, qsimgrs: QSimulationManagers, addr, *args, **kwargs):
        super().__init__(self.text, *args, **kwargs)
        self.disasm_view = disasm_view
        self.qsimgrs = qsimgrs
        self.addr = addr

    def contextMenuEvent(self, event):
        menu = QMenu()
        menu.addAction("Delete", self.delete)
        menu.exec_(QCursor.pos())

    def delete(self):
        raise NotImplementedError


class QFindAddrAnnotation(QExploreAnnotation):
    background_color = QColor(200, 230, 100)
    foreground_color = QColor(30, 80, 30)
    text = "find"

    def delete(self):
        self.qsimgrs.remove_find_address(self.addr)
        self.disasm_view.refresh()


class QAvoidAddrAnnotation(QExploreAnnotation):
    background_color = QColor(230, 200, 100)
    foreground_color = QColor(80, 30, 30)
    text = "avoid"

    def delete(self):
        self.qsimgrs.remove_avoid_address(self.addr)
        self.disasm_view.refresh()


class QBlockAnnotations(QGraphicsItem):
    """Container for all instruction annotations in a QBlock"""

    PADDING = 10

    def __init__(self, addr_to_annotations: dict, *, parent):
        super().__init__(parent=parent)
        self.addr_to_annotations = addr_to_annotations
        max_width = 0
        for addr, annotations in self.addr_to_annotations.items():
            width = sum(a.boundingRect().width() + self.PADDING for a in annotations)
            max_width = max(max_width, width)
            for annotation in annotations:
                annotation.setParentItem(self)
        self.width = max_width
        self._init_widgets()

    def get(self, addr):
        return self.addr_to_annotations.get(addr)

    def width(self):
        return self.boundingRect().width()

    def paint(self, painter, *args, **kwargs):
        pass

    def boundingRect(self):
        return self.childrenBoundingRect()

    def _init_widgets(self):
        # Set the x positions of all the annotations. The y positions will be set later while laying out the
        # instructions
        for addr, annotations in self.addr_to_annotations.items():
            x = self.width
            for annotation in annotations:
                annotation.setX(x - annotation.boundingRect().width())
                x -= annotation.boundingRect().width() + self.PADDING

