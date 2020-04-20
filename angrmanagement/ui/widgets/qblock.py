import logging

from PySide2.QtGui import QColor, QPen, QPainterPath
from PySide2.QtCore import QRectF, QMarginsF

from angr.analyses.disassembly import Instruction
from angr.sim_variable import SimRegisterVariable

from ...utils import get_block_objects, get_out_branches_for_insn
from ...utils.block_objects import FunctionHeader, Variables, PhiVariable, Label
from ...config import Conf
from .qinstruction import QInstruction
from .qfunction_header import QFunctionHeader
from .qblock_label import QBlockLabel
from .qphivariable import QPhiVariable
from .qvariable import QVariable
from .qgraph_object import QCachedGraphicsItem

_l = logging.getLogger(__name__)


class QBlock(QCachedGraphicsItem):
    TOP_PADDING = 5
    BOTTOM_PADDING = 5
    LEFT_PADDING = 10
    RIGHT_PADDING = 10
    SPACING = 0

    def __init__(self, workspace, func_addr, disasm_view, disasm, infodock, addr, cfg_nodes, out_branches, scene,
                 parent=None, container=None):
        super().__init__(parent=parent, container=container)

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
        self.scene = scene

        self._config = Conf

        self.objects = [ ]  # instructions and labels
        self._block_item = None  # type: QPainterPath
        self._block_item_obj = None  # type: QGraphicsPathItem
        self.addr_to_insns = { }
        self.addr_to_labels = { }

        self._init_widgets()

        self._objects_are_hidden = False

        self._create_block_item()

        self.setAcceptHoverEvents(True)

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

    def clear_cache(self):
        super().clear_cache()
        for obj in self.objects:
            obj.clear_cache()

    def refresh(self):
        for obj in self.objects:
            obj.refresh()
        self.layout_widgets()
        self.recalculate_size()
        self._create_block_item()
        self.update()

    def reload(self):
        self._init_widgets()
        self.refresh()

    def size(self):
        return self.width, self.height

    def instruction_position(self, insn_addr):
        if insn_addr in self.addr_to_insns:
            insn = self.addr_to_insns[insn_addr]
            pos = insn.pos()
            return pos.x(), pos.y()

        return None

    #
    # Initialization
    #

    def _create_block_item(self):
        """
        Create the block background and border.
        """
        if self._block_item_obj is not None and self.scene is not None:
            self.scene.removeItem(self._block_item_obj)
            self._block_item = None
            self._block_item_obj = None

        self._block_item = QPainterPath()
        self._block_item.addRect(0, 0, self.width, self.height)

    def _init_widgets(self):

        if self.scene is not None:
            for obj in self.objects:
                self.scene.removeItem(obj)

        self.objects.clear()
        block_objects = get_block_objects(self.disasm, self.cfg_nodes, self.func_addr)

        for obj in block_objects:
            if isinstance(obj, Instruction):
                out_branch = get_out_branches_for_insn(self.out_branches, obj.addr)
                insn = QInstruction(self.workspace, self.func_addr, self.disasm_view, self.disasm,
                                    self.infodock, obj, out_branch, self._config, parent=self,
                                    container=self._container)
                self.objects.append(insn)
                self.addr_to_insns[obj.addr] = insn
            elif isinstance(obj, Label):
                # label
                label = QBlockLabel(obj.addr, obj.text, self._config, self.disasm_view, self.workspace, self.infodock,
                                    parent=self, container=self._container)
                self.objects.append(label)
                self.addr_to_labels[obj.addr] = label
            elif isinstance(obj, PhiVariable):
                if not isinstance(obj.variable, SimRegisterVariable):
                    phivariable = QPhiVariable(self.workspace, self.disasm_view, obj, self._config, parent=self,
                                               container=self._container)
                    self.objects.append(phivariable)
            elif isinstance(obj, Variables):
                for var in obj.variables:
                    variable = QVariable(self.workspace, self.disasm_view, var, self._config, parent=self,
                                         container=self._container)
                    self.objects.append(variable)
            elif isinstance(obj, FunctionHeader):
                self.objects.append(QFunctionHeader(self.func_addr, obj.name, obj.prototype, obj.args, self._config,
                                                    self.disasm_view, self.workspace, self.infodock, parent=self,
                                                    container=self._container))
        self.layout_widgets()

    def layout_widgets(self):
        raise NotImplementedError()


class QGraphBlock(QBlock):
    MINIMUM_DETAIL_LEVEL = 0.4

    @property
    def mode(self):
        return 'graph'

    def layout_widgets(self):
        x, y = self.LEFT_PADDING * self.currentDevicePixelRatioF(), self.TOP_PADDING * self.currentDevicePixelRatioF()
        for obj in self.objects:
            obj.setPos(x, y)
            y += obj.boundingRect().height()

    def hoverEnterEvent(self, event):
        self.infodock.hover_block(self.addr)
        event.accept()

    def hoverLeaveEvent(self, event):
        self.infodock.unhover_block(self.addr)
        event.accept()

    def mousePressEvent(self, event):
        if self.workspace.plugins.handle_click_block(self, event):
            # stop handling this event if the event has been handled by a plugin
            event.accept()
            return

        # the block is selected
        self.on_selected()

        super().mousePressEvent(event)

    def _calc_backcolor(self, should_omit_text):
        color = self.workspace.plugins.color_block(self.addr)
        if color is not None:
            return color

        if should_omit_text:
            return QColor(0xda, 0xda, 0xda)

        return self._config.disasm_view_node_background_color

    def paint(self, painter, option, widget):  # pylint: disable=unused-argument
        lod = option.levelOfDetailFromTransform(painter.worldTransform())
        should_omit_text = lod < QGraphBlock.MINIMUM_DETAIL_LEVEL

        # background of the node
        painter.setBrush(self._calc_backcolor(should_omit_text))
        if self.infodock.is_block_selected(self.addr):
            painter.setPen(QPen(self._config.disasm_view_selected_node_border_color, 2.5))
        else:
            painter.setPen(QPen(self._config.disasm_view_node_border_color, 1.5))
        self._block_item_obj = painter.drawPath(self._block_item)

        # content drawing is handled by qt since children are actual child widgets

        # if we are too far zoomed out, do not draw the text
        if self._objects_are_hidden != should_omit_text:
            for obj in self.objects:
                obj.setVisible(not should_omit_text)
                obj.setEnabled(not should_omit_text)
            self._objects_are_hidden = should_omit_text

        # extra content
        self.workspace.plugins.draw_block(self, painter)

    def on_selected(self):
        self.infodock.select_block(self.addr)

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
            y_offset += self.SPACING * self.currentDevicePixelRatioF()
            obj_start = 0
            obj.setPos(obj_start, y_offset)
            if obj_start + obj.width > max_width:
                max_width = obj_start + obj.boundingRect().width()
            y_offset += obj.boundingRect().height()

        self._height = y_offset
        self._width = max_width

    def paint(self, painter, option, widget):  # pylint: disable=unused-argument
        painter.setFont(self._config.disasm_font)

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
