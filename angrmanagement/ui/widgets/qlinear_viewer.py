import logging

from PySide2.QtWidgets import QWidget, QHBoxLayout, QAbstractSlider
from PySide2.QtGui import QPainter, QWheelEvent
from PySide2.QtCore import Qt
from sortedcontainers import SortedDict

from angr.block import Block
from angr.analyses.cfg.cfb import Unknown, MemoryRegion

from ...config import Conf
from .qgraph import QBaseGraph
from .qblock import QBlock
from .qunknown_block import QUnknownBlock

_l = logging.getLogger('ui.widgets.qlinear_viewer')
# _l.setLevel(logging.DEBUG)


class QLinearGraphicsView(QBaseGraph):
    def __init__(self, viewer, disasm_view, parent=None):
        super(QLinearGraphicsView, self).__init__(viewer.workspace, parent=parent, allow_dragging=False)

        self.viewer = viewer  # type:QLinearViewer
        self.disasm_view = disasm_view
        self._line_height = Conf.disasm_font_height

        self.key_released.connect(self._on_keyreleased_event)

        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.horizontalScrollBar().setSingleStep(Conf.disasm_font_width)
        self.verticalScrollBar().setSingleStep(Conf.disasm_font_height)

        self.verticalScrollBar().actionTriggered.connect(self._on_vertical_scroll_bar_triggered)

    #
    # Events
    #

    def _on_keyreleased_event(self, key_event):

        key = key_event.key()
        if key == Qt.Key_Space:
            self.disasm_view.display_disasm_graph()
            return True
        elif key == Qt.Key_Down:
            self._on_vertical_scroll_bar_triggered(QAbstractSlider.SliderSingleStepAdd)
            return True
        elif key == Qt.Key_Up:
            self._on_vertical_scroll_bar_triggered(QAbstractSlider.SliderSingleStepSub)
            return True
        elif key == Qt.Key_PageDown:
            self._on_vertical_scroll_bar_triggered(QAbstractSlider.SliderPageStepAdd)
            return True
        elif key == Qt.Key_PageUp:
            self._on_vertical_scroll_bar_triggered(QAbstractSlider.SliderPageStepSub)
            return True

        return False

    def _on_vertical_scroll_bar_triggered(self, action):

        if action == QAbstractSlider.SliderSingleStepAdd:
            # scroll down by one line
            self.viewer.prepare_objects(self.viewer.offset, start_line=self.viewer.start_line_in_object + 1)
            self.viewport().update()
        elif action == QAbstractSlider.SliderSingleStepSub:
            # Scroll up by one line
            self.viewer.prepare_objects(self.viewer.offset, start_line=self.viewer.start_line_in_object - 1)
            self.viewport().update()
        elif action == QAbstractSlider.SliderPageStepAdd:
            # Scroll down by one page
            lines_per_page = int(self.height() // self.line_height())
            self.viewer.prepare_objects(self.viewer.offset, start_line=self.viewer.start_line_in_object
                                                                       + lines_per_page)
            self.viewport().update()
        elif action == QAbstractSlider.SliderPageStepSub:
            # Scroll up by one page
            lines_per_page = int(self.height() // self.line_height())
            self.viewer.prepare_objects(self.viewer.offset,
                                        start_line=self.viewer.start_line_in_object - lines_per_page)
            self.viewport().update()
        elif action == QAbstractSlider.SliderMove:
            # Setting a new offset
            new_offset = int(self.verticalScrollBar().value() // self.line_height())
            self.viewer.prepare_objects(new_offset)
            self.viewport().update()

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

    def wheelEvent(self, event):
        """

        :param QWheelEvent event:
        :return:
        """
        delta = event.delta()
        if delta < 0:
            # scroll down by some lines
            self.viewer.prepare_objects(self.viewer.offset, start_line=self.viewer.start_line_in_object + int(-delta // self.line_height()))
        elif delta > 0:
            # Scroll up by some lines
            self.viewer.prepare_objects(self.viewer.offset, start_line=self.viewer.start_line_in_object - int(delta // self.line_height()))
        self.viewport().update()

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

    def line_height(self):
        return self._line_height

    def navigate_to(self, offset):
        self.verticalScrollBar().setValue(offset * self.line_height())

    #
    # Private methods
    #

    def _paint_objects(self, painter):

        x = 80
        y = int(-self.viewer.start_line_in_object * self.line_height())

        for obj in self.viewer.objects:
            obj.x = x
            obj.y = y
            obj.paint(painter)

            y += obj.height

    def _update(self):
        self.verticalScrollBar().setRange(0, self.viewer.max_offset * self.line_height() - self.height() // 2)
        self.verticalScrollBar().setValue(self.viewer.offset * self.line_height())
        # TODO: horizontalScrollbar().setRange()

        self._update_size()

    def _get_object_by_pos(self, pos):
        x, y = pos.x(), pos.y()
        for obj in self.viewer.objects:
            if obj.x is None or obj.y is None:
                continue
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

        self._offset_to_region = SortedDict()
        self._addr_to_region_offset = SortedDict()

        # Offset (in bytes) into the entire blanket view
        self._offset = 0
        # The maximum offset (in bytes) of the blanket view
        self._max_offset = None
        # The first line that is rendered of the first object in self.objects. Start from 0.
        self._start_line_in_object = 0

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
    def start_line_in_object(self):
        return self._start_line_in_object

    @property
    def max_offset(self):
        if self._max_offset is None:
            self._max_offset = self._calculate_max_offset()
        return self._max_offset

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

        if self.cfb is None:
            return

        self._addr_to_region_offset.clear()
        self._offset_to_region.clear()
        self._disasms.clear()
        self._offset = 0
        self._max_offset = None
        self._start_line_in_object = 0

        # enumerate memory regions
        byte_offset = 0
        for mr in self.cfb.regions:  # type:MemoryRegion
            self._addr_to_region_offset[mr.addr] = byte_offset
            self._offset_to_region[byte_offset] = mr
            byte_offset += mr.size

    def navigate_to_addr(self, addr):
        if not self._addr_to_region_offset:
            return
        try:
            floor_region_addr = next(self._addr_to_region_offset.irange(maximum=addr, reverse=True))
        except StopIteration:
            floor_region_addr = next(self._addr_to_region_offset.irange())
        floor_region_offset = self._addr_to_region_offset[floor_region_addr]

        offset_into_region = addr - floor_region_addr
        self.navigate_to(floor_region_offset + offset_into_region)

    def refresh(self):
        self._linear_view.refresh()

    def navigate_to(self, offset):

        self._linear_view.navigate_to(int(offset))

        self.prepare_objects(offset)

        self._linear_view.refresh()

    def prepare_objects(self, offset, start_line=0):
        """
        Prepare objects to print based on offset and start_line. Update self.objects, self._offset, and
        self._start_line_in_object.

        :param int offset:      Beginning offset (in bytes) to display in the linear viewer.
        :param int start_line:  The first line into the first object to display in the linear viewer.
        :return:                None
        """

        if offset == self._offset and start_line == self._start_line_in_object:
            return

        # Convert the offset to memory region
        base_offset, mr = self._region_from_offset(offset)  # type: int,MemoryRegion
        if mr is None:
            return

        addr = self._addr_from_offset(mr, base_offset, offset)
        _l.debug("Address %#x, offset %d, start_line %d.", addr, offset, start_line)

        if start_line < 0:
            # Which object are we currently displaying at the top of the disassembly view?
            try:
                top_obj_addr = self.cfb.floor_addr(addr=addr)
            except KeyError:
                top_obj_addr = addr

            # Reverse-iterate until we have enough lines to compensate start_line
            for obj_addr, obj in self.cfb.ceiling_items(addr=top_obj_addr, reverse=True, include_first=False):
                qobject = self._obj_to_paintable(obj_addr, obj)
                if qobject is None:
                    continue
                object_lines = int(qobject.height // self._linear_view.line_height())
                _l.debug("Compensating negative start_line: object %s, object_lines %d.", obj, object_lines)
                start_line += object_lines
                if start_line >= 0:
                    addr = obj_addr
                    # Update offset
                    new_region_addr = next(self._addr_to_region_offset.irange(maximum=addr, reverse=True))
                    new_region_offset = self._addr_to_region_offset[new_region_addr]
                    offset = (addr - new_region_addr) + new_region_offset
                    break
            else:
                # umm we don't have enough objects to compensate the negative start_line
                start_line = 0
                # update addr and offset to their minimal values
                addr = next(self._addr_to_region_offset.irange())
                offset = self._addr_to_region_offset[addr]

        _l.debug("After adjustment: Address %#x, offset %d, start_line %d.", addr, offset, start_line)

        self.objects = []

        viewable_lines = int(self._linear_view.height() // self._linear_view.line_height())
        lines = 0
        start_line_in_object = 0

        # Load a page of objects
        for obj_addr, obj in self.cfb.floor_items(addr=addr):
            qobject = self._obj_to_paintable(obj_addr, obj)
            if qobject is None:
                # Conversion failed
                continue

            if isinstance(qobject, QBlock):
                for insn_addr in qobject.addr_to_insns.keys():
                    self._linear_view._add_insn_addr_block_mapping(insn_addr, qobject)

            object_lines = int(qobject.height // self._linear_view.line_height())

            if start_line >= object_lines:
                # this object should be skipped. ignore it
                start_line -= object_lines
                # adjust the offset as well
                if obj_addr <= addr < obj_addr + obj.size:
                    offset += obj_addr + obj.size - addr
                else:
                    offset += obj.size
                _l.debug("Skipping object %s (size %d). New offset: %d.", obj, obj.size, offset)
            else:
                if start_line > 0:
                    _l.debug("First object to paint: %s (size %d). Current offset %d.", obj, obj.size, offset)
                    # this is the first object to paint
                    start_line_in_object = start_line
                    start_line = 0
                    lines += object_lines - start_line_in_object
                else:
                    lines += object_lines
                self.objects.append(qobject)

            if lines > viewable_lines:
                break

        _l.debug("Final offset %d, start_line_in_object %d.", offset, start_line_in_object)

        # Update properties
        self._offset = offset
        self._start_line_in_object = start_line_in_object

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

    def _obj_to_paintable(self, obj_addr, obj):
        if isinstance(obj, Block):
            cfg_node = self.cfg.get_any_node(obj.addr, force_fastpath=True)
            if cfg_node is not None:
                func_addr = cfg_node.function_address
                func = self.cfg.kb.functions[func_addr]  # FIXME: Resiliency
                disasm = self._get_disasm(func)
                qobject = QBlock(self.workspace, func_addr, self.disasm_view, disasm,
                                 self.disasm_view.infodock, obj.addr, [obj], {}, mode='linear',
                                 )
            else:
                # TODO: This should be displayed as a function thunk
                _l.error("QLinearViewer: Unexpected result: CFGNode %#x is not found in CFG."
                         "Display it as a QUnknownBlock.", obj.addr)
                qobject = QUnknownBlock(self.workspace, obj_addr, obj.bytes)

        elif isinstance(obj, Unknown):
            qobject = QUnknownBlock(self.workspace, obj_addr, obj.bytes)

        else:
            qobject = None

        return qobject

    def _calculate_max_offset(self):
        try:
            max_off = next(self._offset_to_region.irange(reverse=True))
            mr = self._offset_to_region[max_off]  # type: MemoryRegion
            return max_off + mr.size
        except StopIteration:
            return 0

    def _region_from_offset(self, offset):
        try:
            off = next(self._offset_to_region.irange(maximum=offset, reverse=True))
            return off, self._offset_to_region[off]
        except StopIteration:
            return None, None

    def _addr_from_offset(self, mr, base_offset, offset):
        return mr.addr + (offset - base_offset)

    def _get_disasm(self, func):
        """

        :param func:
        :return:
        """

        if func.addr not in self._disasms:
            self._disasms[func.addr] = self.workspace.instance.project.analyses.Disassembly(function=func)
        return self._disasms[func.addr]
