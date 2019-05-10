import logging

from PySide2.QtGui import QPainter, QLinearGradient, QColor, QBrush, QPen, QPainterPath
from PySide2.QtCore import QPointF, Qt, QRectF, Slot, QMarginsF
from PySide2.QtWidgets import QGraphicsItem

from angr.analyses.disassembly import Instruction
from angr.sim_variable import SimRegisterVariable

from ...utils import (
    get_label_text, get_block_objects, address_to_text, get_out_branches_for_insn,
    get_string_for_display, should_display_string_label,
)
from ...utils.block_objects import Variables, PhiVariable, Label
from ...config import Conf
from .qinstruction import QInstruction
from .qblock_label import QBlockLabel
from .qphivariable import QPhiVariable
from .qvariable import QVariable

from .qgraph_object import QCachedGraphicsItem

_l = logging.getLogger(__name__)
#_l.setLevel(logging.DEBUG)

class QBlock(QCachedGraphicsItem):
    TOP_PADDING = 0
    BOTTOM_PADDING = 0
    LEFT_PADDING = 10
    RIGHT_PADDING = 10
    SPACING = 0

    def __init__(self, workspace, func_addr, disasm_view, disasm, infodock, addr, cfg_nodes, out_branches, parent=None):
        super().__init__(parent=parent)

        # initialization
        self.workspace = workspace
        self.func_addr = func_addr
        self.disasm_view = disasm_view
        self.disasm = disasm
        self.infodock = infodock
        self.variable_manager = infodock.variable_manager
        self.addr = addr
        self.cfg_nodes = cfg_nodes
        self.out_branches = out_branches

        self._config = Conf

        self.objects = [ ]  # instructions and labels
        self.addr_to_insns = { }
        self.addr_to_labels = { }

        self._init_widgets()

        self._objects_are_hidden = False

        self._path = QPainterPath()
        self._path.addRect(0, 0, self.width, self.height)

    #
    # Properties
    #

    @property
    def mode(self):
        raise NotImplementedError

    @property
    def width(self):
        return self.boundingRect().width()

    @property
    def height(self):
        return self.boundingRect().height()

    #
    # Public methods
    #

    @Slot(object)
    def refresh_if_contains_addr(self, addr1, addr2):
        if addr1 in self.addr_to_insns or addr2 in self.addr_to_insns:
            self.refresh()

    def refresh(self):
        self.update()

    def size(self):
        return self.width, self.height

    #
    # Initialization
    #

    def _init_widgets(self):

        self.objects.clear()
        block_objects = get_block_objects(self.disasm, self.cfg_nodes, self.func_addr)

        for obj in block_objects:
            if isinstance(obj, Instruction):
                out_branch = get_out_branches_for_insn(self.out_branches, obj.addr)
                insn = QInstruction(self.workspace, self.func_addr, self.disasm_view, self.disasm,
                                    self.infodock, obj, out_branch, self._config, parent=self)
                self.objects.append(insn)
                self.addr_to_insns[obj.addr] = insn
            elif isinstance(obj, Label):
                # label
                label = QBlockLabel(obj.addr, obj.text, self._config, self.disasm_view, self.workspace, parent=self)
                self.objects.append(label)
                self.addr_to_labels[obj.addr] = label
            # elif isinstance(obj, PhiVariable):
            #     if not isinstance(obj.variable, SimRegisterVariable):
            #         phivariable = QPhiVariable(self.workspace, self.disasm_view, obj, self._config)
            #         self.objects.append(phivariable)
            # elif isinstance(obj, Variables):
            #     for var in obj.variables:
            #         variable = QVariable(self.workspace, self.disasm_view, var, self._config)
            #         self.objects.append(variable)
        self.layout_widgets()

    def layout_widgets(self):
        raise NotImplementedError

    #
    # Private methods
    #

class QGraphBlock(QBlock):
    MINIMUM_DETAIL_LEVEL = 0.4

    @property
    def mode(self):
        return 'graph'

    def layout_widgets(self):
        x, y = self.LEFT_PADDING, self.TOP_PADDING
        for obj in self.objects:
            obj.setPos(x, y)
            y += obj.boundingRect().height()

    def paint(self, painter, option, widget):  #pylint: disable=unused-argument
        lod = option.levelOfDetailFromTransform(painter.worldTransform())
        should_omit_text = lod < QGraphBlock.MINIMUM_DETAIL_LEVEL


        # background of the node
        if should_omit_text:
            painter.setBrush(QColor(0xda, 0xda, 0xda))
        else:
            painter.setBrush(self._config.disasm_view_node_background_color)
        painter.setPen(QPen(self._config.disasm_view_node_border_color, 1.5))
        painter.drawPath(self._path)

        # content

        # if we are two far zoomed out, do not draw the text
        if self._objects_are_hidden != should_omit_text:
            for obj in self.objects:
                obj.setVisible(not should_omit_text)
                obj.setEnabled(not should_omit_text)
            self._objects_are_hidden = should_omit_text

    def _boundingRect(self):
        cbr = self.childrenBoundingRect()
        margins = QMarginsF(self.LEFT_PADDING, self.TOP_PADDING, self.RIGHT_PADDING, self.BOTTOM_PADDING)
        return cbr.marginsAdded(margins)

class QLinearBlock(QBlock):
    ADDRESS_PADDING = 10

    @property
    def mode(self):
        return 'linear'

    def format_address(self, addr):
        return '{:08x}'.format(addr)

    def layout_widgets(self):
        y_offset = 0

        max_width = 0
        for obj in self.objects:
            y_offset += self.SPACING
            addr_width = self._config.disasm_font_metrics.width(self.format_address(obj.addr))
            obj_start = addr_width + self.ADDRESS_PADDING
            obj.setPos(obj_start, y_offset)
            if obj_start + obj.width > max_width:
                max_width = obj_start + obj.width
            y_offset += obj.height
        self._height = y_offset
        self._width = max_width

    def paint(self, painter, option, widget): #pylint: disable=unused-argument
        _l.debug('Painting linear block')
        y_offset = 0
        painter.setFont(self._config.disasm_font)
        for obj in self.objects:
            painter.drawText(0, y_offset+self._config.disasm_font_ascent, '{:08x}'.format(obj.addr))
            y_offset += self._config.disasm_font_height + self.SPACING

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)

