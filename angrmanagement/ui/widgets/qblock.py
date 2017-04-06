
from PySide.QtGui import QPainter, QLinearGradient, QColor, QBrush
from PySide.QtCore import QPointF, Qt

from angr.analyses.disassembly import Instruction

from ...utils import (
    get_label_text, get_block_objects, address_to_text, get_out_branches_for_insn,
    get_string_for_display, should_display_string_label,
)
from .qinstruction import QInstruction
from .qblock_label import QBlockLabel
from .qgraph_object import QGraphObject


class QBlock(QGraphObject):
    TOP_PADDING = 5
    BOTTOM_PADDING = 5
    LEFT_PADDING = 5
    RIGHT_PADDING = 5
    SPACING = 2

    def __init__(self, workspace, disasm_view, disasm, variable_manager, addr, cfg_nodes, out_branches):
        super(QBlock, self).__init__()

        # initialization
        self.workspace = workspace
        self.disasm_view = disasm_view
        self.disasm = disasm
        self.variable_manager = variable_manager
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

        # background of the node
        gradient = QLinearGradient(QPointF(0, self.y), QPointF(0, self.y + self.height))
        gradient.setColorAt(0, QColor(0xff, 0xff, 0xfa))
        gradient.setColorAt(1, QColor(0xff, 0xff, 0xdb))
        painter.setBrush(QBrush(gradient))
        painter.setPen(Qt.black)
        painter.drawRect(self.x, self.y, self.width, self.height)

        # content

        y_offset = 0

        for obj in self.objects:

            y_offset += self.SPACING

            obj.x = self.x + self.LEFT_PADDING
            obj.y = self.y + y_offset
            obj.paint(painter)

            y_offset += self._config.disasm_font_height

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

        block_objects = get_block_objects(self.disasm, self.cfg_nodes)

        for obj in block_objects:
            if isinstance(obj, Instruction):
                out_branch = get_out_branches_for_insn(self.out_branches, obj.addr)
                insn = QInstruction(self.workspace, self.disasm_view, self.disasm, self.variable_manager, obj,
                                    out_branch, self._config
                                    )
                self.objects.append(insn)
                self.addr_to_insns[obj.addr] = insn
            elif isinstance(obj, tuple):
                # label
                addr, text = obj
                label = QBlockLabel(addr, text, self._config)
                self.objects.append(label)
                self.addr_to_labels[addr] = label

        self._update_size()

    def _update_size(self):

        # calculate height
        self._height = self.TOP_PADDING + len(self.objects) * self._config.disasm_font_height + \
                      (len(self.objects) - 1) * self.SPACING + self.BOTTOM_PADDING

        # calculate width
        self._width = self.LEFT_PADDING + max([obj.width for obj in self.objects]) + self.RIGHT_PADDING
