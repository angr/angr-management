
from PySide.QtGui import QPainter, QLinearGradient, QColor, QBrush, QPen
from PySide.QtCore import QPointF, Qt

from angr.analyses.disassembly import Instruction

from ...utils import (
    get_label_text, get_block_objects, address_to_text, get_out_branches_for_insn,
    get_string_for_display, should_display_string_label,
)
from ...utils.block_objects import Variables, Label
from .qinstruction import QInstruction
from .qblock_label import QBlockLabel
from .qvariable import QVariable
from .qgraph_object import QGraphObject


class QBlock(QGraphObject):
    TOP_PADDING = 5
    BOTTOM_PADDING = 5
    LEFT_PADDING = 10
    RIGHT_PADDING = 10
    SPACING = 0

    def __init__(self, workspace, func_addr, disasm_view, disasm, infodock, addr, cfg_nodes, out_branches):
        super(QBlock, self).__init__()

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

        self._config = workspace

        self.objects = [ ]  # instructions and labels
        self.addr_to_insns = { }
        self.addr_to_labels = { }

        self._init_widgets()

    #
    # Properties
    #

    @property
    def x(self):
        return self._x

    @x.setter
    def x(self, v):
        self._x = v

    @property
    def y(self):
        return self._y

    @y.setter
    def y(self, v):
        self._y = v

    @property
    def width(self):
        if self._width is None:
            self._update_size()
        return self._width

    @property
    def height(self):
        if self._height is None:
            self._update_size()
        return self._height

    #
    # Public methods
    #

    def refresh(self):
        super(QBlock, self).refresh()

        for obj in self.objects:
            obj.refresh()

        self._update_size()

    def update_label(self, label_addr):
        label = self.addr_to_labels.get(label_addr, None)
        if label is not None:
            label.label = self.disasm.kb.labels[label_addr]
        else:
            raise Exception('Label at address %#x is not found.' % label_addr)

    def instruction_position(self, insn_addr):
        if insn_addr in self.addr_to_insns:
            insn = self.addr_to_insns[insn_addr]
            x = self.x + self.LEFT_PADDING
            y = self.y + self.TOP_PADDING + self.objects.index(insn) * (self._config.disasm_font_height + self.SPACING)
            return x, y

        return None

    def size(self):
        return self.width, self.height

    def paint(self, painter):
        """

        :param QPainter painter:
        :return:
        """

        # shadow
        # painter.setPen(QColor(0, 0, 0, 0))
        # painter.setBrush(QColor(0, 0, 0, 0x80))
        # painter.drawRect(self.x + 3, self.y + 3, self.width, self.height)

        # background of the node
        gradient = QLinearGradient(QPointF(0, self.y), QPointF(0, self.y + self.height))
        gradient.setColorAt(0, QColor(0xff, 0xff, 0xfa))
        gradient.setColorAt(1, QColor(0xff, 0xff, 0xdb))
        #painter.setBrush(QBrush(gradient))
        painter.setBrush(QColor(0xfa, 0xfa, 0xfa))
        painter.setPen(QPen(QColor(0xf0, 0xf0, 0xf0), 1.5))
        # painter.setPen(QPen(QBrush(Qt.gray), 1))
        painter.drawRect(self.x, self.y, self.width, self.height)

        # content

        y_offset = self.TOP_PADDING

        for obj in self.objects:

            y_offset += self.SPACING

            obj.x = self.x + self.LEFT_PADDING
            obj.y = self.y + y_offset
            obj.paint(painter)

            y_offset += obj.height

    #
    # Event handlers
    #

    def on_mouse_pressed(self, button, pos):
        for obj in self.objects:
            if obj.y <= pos.y() < obj.y + obj.height:
                obj.on_mouse_pressed(button, pos)
                break

    def on_mouse_released(self, button, pos):
        for obj in self.objects:
            if obj.y <= pos.y() < obj.y + obj.height:
                obj.on_mouse_released(button, pos)
                break

    def on_mouse_doubleclicked(self, button, pos):
        for obj in self.objects:
            if obj.y <= pos.y() < obj.y + obj.height:
                obj.on_mouse_doubleclicked(button, pos)
                break

    #
    # Initialization
    #

    def _init_widgets(self):

        block_objects = get_block_objects(self.disasm, self.cfg_nodes, self.func_addr)

        for obj in block_objects:
            if isinstance(obj, Instruction):
                out_branch = get_out_branches_for_insn(self.out_branches, obj.addr)
                insn = QInstruction(self.workspace, self.func_addr, self.disasm_view, self.disasm,
                                    self.infodock, obj, out_branch, self._config
                                    )
                self.objects.append(insn)
                self.addr_to_insns[obj.addr] = insn
            elif isinstance(obj, Label):
                # label
                label = QBlockLabel(obj.addr, obj.text, self._config)
                self.objects.append(label)
                self.addr_to_labels[obj.addr] = label
            elif isinstance(obj, Variables):
                for var in obj.variables:
                    variable = QVariable(self.workspace, self.disasm_view, var, self._config)
                    self.objects.append(variable)

        self._update_size()

    def _update_size(self):

        # calculate height
        self._height = self.TOP_PADDING + len(self.objects) * self._config.disasm_font_height + \
                      (len(self.objects) - 1) * self.SPACING + self.BOTTOM_PADDING

        # calculate width
        self._width = self.LEFT_PADDING + (max([obj.width for obj in self.objects]) if self.objects else 0) +\
                      self.RIGHT_PADDING
