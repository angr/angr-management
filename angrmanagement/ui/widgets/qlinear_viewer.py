from typing import Optional, TYPE_CHECKING, Union
import logging
from sortedcontainers import SortedDict

from PySide2.QtWidgets import QGraphicsScene, QAbstractSlider, QHBoxLayout, QAbstractScrollArea
from PySide2.QtGui import QPainter
from PySide2.QtCore import Qt, QRectF, QRect, QEvent

from angr.block import Block
from angr.knowledge_plugins.cfg.memory_data import MemoryData
from angr.knowledge_plugins import Function
from angr.analyses.cfg.cfb import Unknown
from angr.analyses.decompiler import Clinic
from angr.analyses import Disassembly

from ...config import Conf
from .qblock import QLinearBlock
from .qmemory_data_block import QMemoryDataBlock
from .qunknown_block import QUnknownBlock
from .qgraph import QSaveableGraphicsView
from .qdisasm_base_control import QDisassemblyBaseControl, DisassemblyLevel

if TYPE_CHECKING:
    from angrmanagement.logic.disassembly import InfoDock


_l = logging.getLogger(__name__)


class QLinearDisassemblyView(QSaveableGraphicsView):

    def __init__(self, area, parent=None):
        super().__init__(parent=parent)

        self.area = area  # type: QLinearDisassembly
        self._scene = QGraphicsScene(0, 0, self.width(), self.height())
        self.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.setScene(self._scene)
        self.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform |
                            QPainter.HighQualityAntialiasing)

        # Do not use the scrollbars since they are hard-linked to the size of the scene, which is bad for us
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

    def wheelEvent(self, event):
        self.area.wheelEvent(event)
        super().wheelEvent(event)

    def event(self, event):
        """
        Reimplemented to capture the Tab keypress event.
        """

        # by default, the tab key moves focus. Hijack the tab key
        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Tab:
            self.area.disasm_view.keyPressEvent(event)
            return True
        return super().event(event)


class QLinearDisassembly(QDisassemblyBaseControl, QAbstractScrollArea):
    OBJECT_PADDING = 0

    def __init__(self, workspace, disasm_view, parent=None):
        QDisassemblyBaseControl.__init__(self, workspace, disasm_view, QAbstractScrollArea)
        QAbstractScrollArea.__init__(self, parent=parent)

        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.horizontalScrollBar().setSingleStep(Conf.disasm_font_width)
        self.verticalScrollBar().setSingleStep(16)

        # self.setTransformationAnchor(QGraphicsView.NoAnchor)
        # self.setResizeAnchor(QGraphicsView.NoAnchor)
        # self.setAlignment(Qt.AlignLeft)

        self._viewer = None  # type: QLinearDisassemblyView

        self._line_height = Conf.disasm_font_height

        self._offset_to_region = SortedDict()
        self._addr_to_region_offset = SortedDict()
        # Offset (in bytes) into the entire blanket view
        self._offset = 0
        # The maximum offset (in bytes) of the blanket view
        self._max_offset = None
        # The first line that is rendered of the first object in self.objects. Start from 0.
        self._start_line_in_object = 0

        self._disasms = { }
        self._ail_disasms = { }
        self.objects = [ ]

        self.verticalScrollBar().actionTriggered.connect(self._on_vertical_scroll_bar_triggered)

        self._init_widgets()

    def reload(self, old_infodock: Optional['InfoDock']=None):
        curr_offset = self._offset
        self.initialize()
        self._offset = None  # force a re-generation of objects
        self.prepare_objects(curr_offset, start_line=self._start_line_in_object)
        self.redraw()

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
    def max_offset(self):
        if self._max_offset is None:
            self._max_offset = self._calculate_max_offset()
        return self._max_offset

    @property
    def cfg(self):
        return self.workspace.instance.cfg

    @property
    def cfb(self):
        return self.workspace.instance.cfb

    @property
    def scene(self):
        return self._viewer._scene

    #
    # Events
    #

    def resizeEvent(self, event):
        old_height = event.oldSize().height()
        new_height = event.size().height()
        self._viewer._scene.setSceneRect(QRectF(0, 0, event.size().width(), new_height))

        if new_height > old_height:
            # we probably need more objects generated
            curr_offset = self._offset
            self._offset = None  # force a re-generation of objects
            self.prepare_objects(curr_offset, start_line=self._start_line_in_object)
            self.redraw()

        super().resizeEvent(event)

    def wheelEvent(self, event):
        """
        :param QWheelEvent event:
        :return:
        """
        delta = event.delta()
        if delta < 0:
            # scroll down by some lines
            lines = min(int(-delta // self._line_height), 3)
            self.prepare_objects(self.offset, start_line=self._start_line_in_object + lines)
        elif delta > 0:
            # Scroll up by some lines
            lines = min(int(delta // self._line_height), 3)
            self.prepare_objects(self.offset, start_line=self._start_line_in_object - lines)

        self.verticalScrollBar().setValue(self.offset * self._line_height)
        event.accept()
        self.viewport().update()

    def changeEvent(self, event: QEvent):
        """
        Redraw on color scheme update.
        """
        if event.type() == QEvent.PaletteChange:
            self.reload()

    def _on_vertical_scroll_bar_triggered(self, action):

        if action == QAbstractSlider.SliderSingleStepAdd:
            # scroll down by one line
            self.prepare_objects(self.offset, start_line=self._start_line_in_object + 1)
            self.viewport().update()
        elif action == QAbstractSlider.SliderSingleStepSub:
            # Scroll up by one line
            self.prepare_objects(self.offset, start_line=self._start_line_in_object - 1)
            self.viewport().update()
        elif action == QAbstractSlider.SliderPageStepAdd:
            # Scroll down by one page
            lines_per_page = int(self.height() // self._line_height)
            self.prepare_objects(self.offset, start_line=self._start_line_in_object
                                                                       + lines_per_page)
            self.viewport().update()
        elif action == QAbstractSlider.SliderPageStepSub:
            # Scroll up by one page
            lines_per_page = int(self.height() // self._line_height)
            self.prepare_objects(self.offset,
                                        start_line=self._start_line_in_object - lines_per_page)
            self.viewport().update()
        elif action == QAbstractSlider.SliderMove:
            # Setting a new offset
            new_offset = int(self.verticalScrollBar().value() // self._line_height)
            self.prepare_objects(new_offset)
            self.viewport().update()

    #
    # Public methods
    #

    def redraw(self):
        if self._viewer is not None:
            self._viewer.redraw()

    def refresh(self):
        self._update_size()
        self.redraw()

    def initialize(self):

        if self.cfb.am_none:
            return

        self._addr_to_region_offset.clear()
        self._offset_to_region.clear()
        self._disasms.clear()
        self._ail_disasms.clear()
        self._offset = None
        self._max_offset = None
        self._start_line_in_object = 0

        # enumerate memory regions
        byte_offset = 0
        for mr in self.cfb.regions:  # type: MemoryRegion
            if mr.type in {'tls', 'kernel'}:
                # Skip TLS objects and kernel objects
                continue
            self._addr_to_region_offset[mr.addr] = byte_offset
            self._offset_to_region[byte_offset] = mr
            byte_offset += mr.size

        self.refresh()

    def goto_function(self, func):
        if func.addr not in self._block_addr_map:
            _l.error('Unable to find entry block for function %s', func)
        view_height = self.viewport().height()
        desired_center_y = self._block_addr_map[func.addr].pos().y()
        _l.debug('Going to function at 0x%x by scrolling to %s', func.addr, desired_center_y)
        self.verticalScrollBar().setValue(desired_center_y - (view_height / 3))

    def show_instruction(self, insn_addr, insn_pos=None, centering=False, use_block_pos=False, use_animation=False):
        """

        :param insn_addr:
        :param QGraphicsItem item:
        :param centering:
        :param use_block_pos:
        :return:
        """

        if insn_pos is not None:
            # check if item is already visible in the viewport
            viewport = self._viewer.viewport()
            rect = self._viewer.mapToScene(QRect(0, 0, viewport.width(), viewport.height())).boundingRect()
            if rect.contains(insn_pos):
                return

        self.navigate_to_addr(insn_addr)

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

    def navigate_to(self, offset):
        self.verticalScrollBar().setValue(offset * self._line_height)
        self.prepare_objects(offset, start_line=0)

    #
    # Private methods
    #

    def _init_widgets(self):
        self._viewer = QLinearDisassemblyView(self)

        layout = QHBoxLayout()
        layout.addWidget(self._viewer)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    def _update_size(self):

        # ask all objects to update their sizes
        for obj in self.objects:
            obj.clear_cache()
            obj.refresh()

        # update vertical scrollbar
        self.verticalScrollBar().setRange(0, self.max_offset * self._line_height - self.height() // 2)
        offset = 0 if self.offset is None else self.offset
        self.verticalScrollBar().setValue(offset * self._line_height)

    def clear_objects(self):
        self.objects.clear()
        self._offset = None

    def prepare_objects(self, offset, start_line=0):
        """
        Prepare objects to print based on offset and start_line. Update self.objects, self._offset, and
        self._start_line_in_object.
        :param int offset:      Beginning offset (in bytes) to display in the linear viewer.
        :param int start_line:  The first line into the first object to display in the linear viewer.
        :return:                None
        """

        if offset is None:
            offset = 0

        if offset == self._offset and start_line == self._start_line_in_object:
            return

        # Convert the offset to memory region
        base_offset, mr = self._region_from_offset(offset)  # type: int, MemoryRegion
        if mr is None:
            return

        addr = self._addr_from_offset(mr, base_offset, offset)
        _l.debug("Address %#x, offset %d, start_line %d.", addr, offset, start_line)

        self._insaddr_to_block.clear()

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
                object_lines = int(qobject.height // self._line_height)
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

        scene = self.scene
        # remove existing objects
        for obj in self.objects:
            scene.removeItem(obj)
        self.objects = [ ]

        viewable_lines = int(self.height() // self._line_height)
        lines = 0
        start_line_in_object = 0

        # Load a page of objects
        x = 80
        y = -start_line * self._line_height

        for obj_addr, obj in self.cfb.floor_items(addr=addr):
            qobject = self._obj_to_paintable(obj_addr, obj)
            _l.debug("Converted %s to %s at %x.", obj, qobject, obj_addr)
            if qobject is None:
                # Conversion failed
                continue

            if isinstance(qobject, QLinearBlock):
                for insn_addr in qobject.addr_to_insns.keys():
                    self._insaddr_to_block[insn_addr] = qobject

            # qobject.setCacheMode(QGraphicsItem.DeviceCoordinateCache)

            object_lines = int(qobject.height // self._line_height)

            if start_line > 0 and start_line >= object_lines:
                # this object should be skipped. ignore it
                start_line -= object_lines
                # adjust the offset as well
                if obj_addr <= addr < obj_addr + obj.size:
                    offset += obj_addr + obj.size - addr
                else:
                    offset += obj.size
                _l.debug("Skipping object %s (size %d). New offset: %d.", obj, obj.size, offset)
                y = -start_line * self._line_height
            else:
                if start_line > 0:
                    _l.debug("First object to paint: %s (size %d). Current offset %d. Start printing from line %d. "
                             "Y pos %d.", obj, obj.size, offset, start_line, y)
                    # this is the first object to paint
                    start_line_in_object = start_line
                    start_line = 0
                    lines += object_lines - start_line_in_object
                else:
                    lines += object_lines
                self.objects.append(qobject)
                qobject.setPos(x, y)
                _l.debug("Adding object %s (height %s) at position %d, %d.", qobject, qobject.height, x, y)
                scene.addItem(qobject)
                y += qobject.height + self.OBJECT_PADDING

            if lines > viewable_lines:
                break

        _l.debug("Final offset %d, start_line_in_object %d.", offset, start_line_in_object)

        # Update properties
        self._offset = offset
        self._start_line_in_object = start_line_in_object

    def _obj_to_paintable(self, obj_addr, obj):
        if isinstance(obj, Block):
            cfg_node = self.cfg.get_any_node(obj_addr, force_fastpath=True)
            if cfg_node is not None:
                func_addr = cfg_node.function_address
                if self.workspace.instance.kb.functions.contains_addr(func_addr):
                    func = self.workspace.instance.kb.functions[func_addr]
                    disasm = self._get_disasm(func)
                    qobject = None
                    if self._disassembly_level is DisassemblyLevel.AIL:
                        ail_obj = None
                        if disasm.graph is not None:
                            # Clinic may yield a None graph when the function is empty
                            for n in disasm.graph.nodes:
                                if n.addr == obj.addr:
                                    ail_obj = n
                            # the corresponding AIL block may not exist
                            if ail_obj is not None:
                                qobject = QLinearBlock(self.workspace, func_addr, self.disasm_view, disasm,
                                                       self.disasm_view.infodock, obj.addr, ail_obj, None, None
                                                       )
                    else:
                        qobject = QLinearBlock(self.workspace, func_addr, self.disasm_view, disasm,
                                               self.disasm_view.infodock, obj.addr, [obj], {}, None
                                               )
                else:
                    # TODO: Get disassembly even if the function does not exist
                    _l.warning("Function %s does not exist, and we cannot get disassembly for block %s.",
                               func_addr, obj)
                    qobject = None
            else:
                _l.warning("Failed to get a CFG node for address %#x.", obj_addr)
                qobject = None
        elif isinstance(obj, MemoryData):
            qobject = QMemoryDataBlock(self.workspace, self.disasm_view.infodock, obj_addr, obj, parent=None)
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

    def _get_disasm(self, func: Function) -> Optional[Union[Clinic, Disassembly]]:
        """
        Get disassembly analysis object for a given function
        """
        if self._disassembly_level is DisassemblyLevel.AIL:
            if func.addr not in self._ail_disasms:
                self._ail_disasms[func.addr] = self.workspace.instance.project.analyses.Clinic(func)
            return self._ail_disasms[func.addr]

        if func.addr not in self._disasms:
            include_ir = self._disassembly_level is DisassemblyLevel.LifterIR
            self._disasms[func.addr] = self.workspace.instance.project.analyses.Disassembly(function=func, include_ir=include_ir)
        return self._disasms[func.addr]
