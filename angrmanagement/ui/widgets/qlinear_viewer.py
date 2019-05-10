import logging

from PySide2.QtWidgets import QWidget, QHBoxLayout, QAbstractSlider, QGraphicsView, QGraphicsScene, QGraphicsItem
from PySide2.QtGui import QPainter, QWheelEvent, QPixmapCache
from PySide2.QtCore import Qt, QPointF, Slot, QPoint, QMarginsF
from sortedcontainers import SortedDict

from angr.block import Block
from angr.analyses.cfg.cfb import Unknown, MemoryRegion

from ...config import Conf
from .qblock import QLinearBlock
from .qunknown_block import QUnknownBlock
from .qgraph import QSaveableGraphicsView

_l = logging.getLogger(__name__)

class QLinearDisassembly(QSaveableGraphicsView):
    OBJECT_PADDING = 0

    def __init__(self, workspace, disasm_view, parent=None):
        super().__init__(parent=parent)

        self.workspace = workspace
        self.disasm_view = disasm_view

        self.setScene(QGraphicsScene(self))

        self.workspace.instance.subscribe_to_cfg(lambda *args, **kwargs: self.reload())
        self.workspace.instance.subscribe_to_cfb(lambda *args, **kwargs: self.reload())
        # TODO: Reimplement me
        # self.workspace.instance.subscribe_to_selected_function(lambda old, new: self.goto_function(new))

        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)

        self.setTransformationAnchor(QGraphicsView.NoAnchor)
        self.setResizeAnchor(QGraphicsView.NoAnchor)
        self.setAlignment(Qt.AlignLeft)


        self._disasms = { }
        self.objects = []
        self._add_items()
        self._block_addr_map = {}

    def redraw(self):
        self.scene().update(self.sceneRect())

    def reload(self):
        self._add_items()

    def goto_function(self, func):
        if func.addr not in self._block_addr_map:
            _l.error('Unable to find entry block for function %s', func)
        view_height = self.viewport().height()
        desired_center_y = self._block_addr_map[func.addr].pos().y()
        _l.debug('Going to function at 0x%x by scrolling to %s', func.addr, desired_center_y)
        self.verticalScrollBar().setValue(desired_center_y - (view_height / 3))

    @property
    def cfg(self):
        return self.workspace.instance.cfg

    @property
    def cfb(self):
        return self.workspace.instance.cfb

    def _add_items(self):
        self.objects.clear()
        if self.cfb is None or self.cfg is None:
            return
        _l.debug('Reloading the whole linear disassembly')
        self.scene().clear()
        x, y = 0, 0
        _l.debug('Refreshing QLinear')
        if self.cfb is None:
            return
        maxwidth = 0
        for obj_addr, obj in self.cfb.floor_items():
            if isinstance(obj, Block):
                cfg_node = self.cfg.get_any_node(obj_addr, force_fastpath=True)
                func_addr = cfg_node.function_address
                func = self.cfg.kb.functions[func_addr]  # FIXME: Resiliency
                disasm = self._get_disasm(func)
                qobject = QLinearBlock(self.workspace, func_addr, self.disasm_view, disasm,
                                 self.disasm_view.infodock, obj.addr, [obj], {},
                                 )
            elif isinstance(obj, Unknown):
                qobject = QUnknownBlock(self.workspace, obj_addr, obj.bytes)
            else:
                continue
            self.objects.append(qobject)
            self._block_addr_map[obj_addr] = qobject
            qobject.setCacheMode(QGraphicsItem.DeviceCoordinateCache)
            y += qobject.height + self.OBJECT_PADDING
            if qobject.width > maxwidth:
                maxwidth = qobject.width

        # QGraphicsScene does not perform well when not centered around 0
        # https://stackoverflow.com/questions/6164543/qgraphicsscene-item-coordinates-affect-performance
        totalheight = y
        half_maxwidth = maxwidth / 2
        half_totalheight = totalheight / 2
        self.scene().setSceneRect(- half_maxwidth, - half_totalheight, maxwidth, totalheight)
        y = -1 * (totalheight / 2)
        for obj in self.objects:
            self.scene().addItem(obj)
            obj.setPos(x, y)
            y += obj.height + self.OBJECT_PADDING

        margins = QMarginsF(50, 25, 10, 25)

        itemsBoundingRect = self.scene().itemsBoundingRect()
        paddedRect = itemsBoundingRect.marginsAdded(margins)
        self.setSceneRect(paddedRect)
        self.verticalScrollBar().setValue(self.verticalScrollBar().minimum())
        self.horizontalScrollBar().setValue(self.horizontalScrollBar().minimum())

    def _get_disasm(self, func):
        """

        :param func:
        :return:
        """

        if func.addr not in self._disasms:
            self._disasms[func.addr] = self.workspace.instance.project.analyses.Disassembly(function=func)
        return self._disasms[func.addr]
