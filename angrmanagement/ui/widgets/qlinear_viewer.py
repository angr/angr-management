import logging

from PySide2.QtWidgets import QWidget, QHBoxLayout
from PySide2.QtGui import QPainter
from PySide2.QtCore import Qt
from sortedcontainers import SortedDict

from angr.block import Block
from angr.analyses.cfg.cfb import Unknown

from ...config import Conf
from .qgraph import QBaseGraph
from .qblock import QBlock
from .qunknown_block import QUnknownBlock

_l = logging.getLogger('ui.widgets.qlinear_viewer')


class QLinearGraphicsView(QBaseGraph):
    def __init__(self, viewer, disasm_view, parent=None):
        super(QLinearGraphicsView, self).__init__(viewer.workspace, parent)

        self.viewer = viewer
        self.disasm_view = disasm_view

        self.key_released.connect(self._on_keyreleased_event)

        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.horizontalScrollBar().setSingleStep(Conf.disasm_font_width)
        self.verticalScrollBar().setSingleStep(Conf.disasm_font_height)

    #
    # Events
    #

    def _on_keyreleased_event(self, key_event):

        key = key_event.key()
        if key == Qt.Key_Space:
            self.disasm_view.display_disasm_graph()
            return True

        return False

    def mousePressEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if event.button() == Qt.LeftButton:
            block = self._get_object_by_pos(event.pos())
            if block is not None:
                # clicking on a block
                block.on_mouse_pressed(event.button(), event.pos())
                event.accept()
                return

        super(QLinearGraphicsView, self).mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if event.button() == Qt.RightButton:
            block = self._get_object_by_pos(event.pos())
            if block is not None:
                block.on_mouse_released(event.button(), event.pos())
            event.accept()
            return

        super(QLinearGraphicsView, self).mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if event.button() == Qt.LeftButton:
            block = self._get_object_by_pos(event.pos())
            if block is not None:
                block.on_mouse_doubleclicked(event.button(), event.pos())
            event.accept()
            return True

    def resizeEvent(self, event):

        self._update_size()

    def paintEvent(self, event):
        """
        Paint the linear view.

        :param event:
        :return:
        """

        painter = QPainter(self.viewport())

        # Set the disassembly font
        painter.setFont(Conf.disasm_font)

        self._paint_objects(painter)

    #
    # Public methods
    #

    def refresh(self):

        self._update()
        self.viewport().update()

    def request_relayout(self):
        pass

    def show_instruction(self, insn_addr):
        # Don't do anything
        pass

    #
    # Private methods
    #

    def _paint_objects(self, painter):

        new_offset = self.verticalScrollBar().value()

        self.viewer.prepare_objects(new_offset)

        x = 80
        y = self.viewer.paint_start_offset - self.viewer.offset

        for obj in self.viewer.objects:
            obj.x = x
            obj.y = y
            obj.paint(painter)

            y += obj.height

    def _update(self):
        self.verticalScrollBar().setRange(0, self.viewer.max_offset - self.height() // 2)
        self.verticalScrollBar().setValue(self.viewer.offset)
        # TODO: horizontalScrollbar().setRange()

        self._update_size()

    def _get_object_by_pos(self, pos):
        x, y = pos.x(), pos.y()
        for obj in self.viewer.objects:
            if obj.x <= x <= obj.x + obj.width and \
                    obj.y <= y <= obj.y + obj.height:
                return obj
        return None


class QLinearViewer(QWidget):
    def __init__(self, workspace, disasm_view, parent=None):
        super(QLinearViewer, self).__init__(parent)

        self.workspace = workspace
        self.disasm_view = disasm_view

        self.objects = [ ]  # Objects that will be painted

        self.cfg = None
        self.cfb = None
        self._offset_to_addr = SortedDict()
        self._addr_to_offset = SortedDict()
        self._offset_to_object = SortedDict()
        self._offset = 0
        self._paint_start_offset = 0

        self._linear_view = None  # type: QLinearGraphicsView
        self._disasms = { }

        self._init_widgets()

    #
    # Properties
    #

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, v):
        self._offset = v

    @property
    def paint_start_offset(self):
        return self._paint_start_offset

    @property
    def max_offset(self):

        # TODO: Cache it

        try:
            max_off = next(self._offset_to_object.irange(reverse=True))
            obj = self._offset_to_object[max_off]
        except StopIteration:
            return 0

        return max_off + obj.height

    #
    # Proxy properties
    #

    @property
    def selected_operands(self):
        return self._linear_view.selected_operands

    @property
    def selected_insns(self):
        return self._linear_view.selected_insns

    #
    # Public methods
    #

    def initialize(self):
        self._make_objects()

    def navigate_to_addr(self, addr):
        if not self._addr_to_offset:
            return
        try:
            floor_addr = next(self._addr_to_offset.irange(maximum=addr, reverse=True))
        except StopIteration:
            floor_addr = next(self._addr_to_offset.irange())
        floor_offset = self._addr_to_offset[floor_addr]
        self.navigate_to(floor_offset)

    def refresh(self):
        self._linear_view.refresh()

    def navigate_to(self, offset):

        self._linear_view.verticalScrollBar().setValue(int(offset))

        self.prepare_objects(offset)

        self._linear_view.refresh()

    def prepare_objects(self, offset):

        if offset == self._offset:
            return

        try:
            start_offset = next(self._offset_to_object.irange(maximum=offset, reverse=True))
        except StopIteration:
            try:
                start_offset = next(self._offset_to_object.irange())
            except StopIteration:
                # Tree is empty
                return

        # Update offset
        self._offset = offset
        self._paint_start_offset = start_offset

        self.objects = [ ]
        max_height = self.height()

        for off in self._offset_to_object.irange(minimum=start_offset):
            obj = self._offset_to_object[off]
            self.objects.append(obj)
            if off - offset > max_height:
                break

    #
    # Private methods
    #

    def _init_widgets(self):

        self._linear_view = QLinearGraphicsView(self, self.disasm_view)

        layout = QHBoxLayout()
        layout.addWidget(self._linear_view)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

        # Setup proxy methods
        self.update_label = self._linear_view.update_label
        self.select_instruction = self._linear_view.select_instruction
        self.unselect_instruction = self._linear_view.unselect_instruction
        self.unselect_all_instructions = self._linear_view.unselect_all_instructions
        self.select_operand = self._linear_view.select_operand
        self.unselect_operand = self._linear_view.unselect_operand
        self.unselect_all_operands = self._linear_view.unselect_all_operands
        self.show_selected = self._linear_view.show_selected
        self.show_instruction = self._linear_view.show_instruction

    def _make_objects(self):

        self._addr_to_offset.clear()
        self._offset_to_addr.clear()
        self._offset_to_object.clear()

        y = 0

        self._linear_view._clear_insn_addr_block_mapping()

        for obj_addr, obj in self.cfb.floor_items():

            if isinstance(obj, Block):
                cfg_node = self.cfg.get_any_node(obj.addr)
                if cfg_node is not None:
                    func_addr = cfg_node.function_address
                    func = self.cfg.kb.functions[func_addr]  # FIXME: Resiliency
                    disasm = self._get_disasm(func)
                    qobject = QBlock(self.workspace, func_addr, self.disasm_view, disasm,
                                     self.disasm_view.infodock, obj.addr, [ obj ], { }, mode='linear',
                                     )

                    for insn_addr in qobject.addr_to_insns.keys():
                        self._linear_view._add_insn_addr_block_mapping(insn_addr, qobject)
                else:
                    # TODO: This should be displayed as a function thunk
                    _l.error("QLinearViewer: Unexpected result: CFGNode %#x is not found in CFG."
                             "Display it as a QUnknownBlock.", obj.addr)
                    qobject = QUnknownBlock(self.workspace, obj_addr, obj.bytes)

            elif isinstance(obj, Unknown):
                qobject = QUnknownBlock(self.workspace, obj_addr, obj.bytes)

            else:
                continue

            self._offset_to_object[y] = qobject
            if obj_addr not in self._addr_to_offset:
                self._addr_to_offset[obj_addr] = y
            y += qobject.height

    def _get_disasm(self, func):
        """

        :param func:
        :return:
        """

        if func.addr not in self._disasms:
            self._disasms[func.addr] = self.workspace.instance.project.analyses.Disassembly(function=func)
        return self._disasms[func.addr]
