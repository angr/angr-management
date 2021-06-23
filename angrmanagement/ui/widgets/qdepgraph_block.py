from typing import TYPE_CHECKING, Optional
import logging

import PySide2.QtWidgets
from PySide2.QtGui import QColor, QPen
from PySide2.QtCore import Qt, QRectF
from PySide2.QtWidgets import QGraphicsSimpleTextItem

from angr.knowledge_plugins.key_definitions.atoms import Atom, Register, MemoryLocation, SpOffset

from ...config import Conf
from ...utils import locate_function, get_string_for_display
from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angr.knowledge_plugins.key_definitions.definition import Definition
    from angrmanagement.ui.views.dep_view import DependencyView


_l = logging.getLogger(__name__)


class QDepGraphBlock(QCachedGraphicsItem):

    HORIZONTAL_PADDING = 20
    VERTICAL_PADDING = 20
    LINE_MARGIN = 3

    def __init__(self, is_selected, dep_view: 'DependencyView', definition: 'Definition'=None, atom: Atom=None,
                 addr: int=None):
        super().__init__()

        self._dep_view = dep_view
        self._workspace = self._dep_view.workspace
        self._config = Conf

        self.selected = is_selected

        # widgets
        self._definition_str: str = None
        self._definition_item: QGraphicsSimpleTextItem = None
        self._instruction_str: str = None
        self._instruction_item: QGraphicsSimpleTextItem = None
        self._function_str: str = None
        self._function_item: QGraphicsSimpleTextItem = None
        self._text: Optional[str] = None
        self._text_item: Optional[QGraphicsSimpleTextItem] = None

        self.definition = definition
        self.atom = atom
        self.addr = addr

        self._init_widgets()
        self._update_size()

        self.setAcceptHoverEvents(True)

    def _init_widgets(self):

        # definition
        self._definition_str = ""
        if self.definition is not None:
            atom = self.definition.atom
        else:
            atom = self.atom
        addr_str = "unknown address" if self.addr is None else "%#x" % self.addr
        if isinstance(atom, Register):
            # convert it to a register name
            arch = self._workspace.instance.project.arch
            register_name = arch.translate_register_name(atom.reg_offset, size=atom.size)
            self._definition_str = "Register {} @ {}".format(register_name, addr_str)
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                self._definition_str = "Stack sp%+#x @ %s" % (atom.addr.offset, addr_str)
            elif isinstance(atom.addr, int):
                self._definition_str = "Memory %#x @ %s" % (atom.addr, addr_str)

        if not self._definition_str:
            # fallback
            self._definition_str = repr(self.definition.atom)

        # function and instruction text

        if self.addr is None:
            self._function_str = "Unknown"
            self._instruction_str = "Unknown"
        else:
            # function string
            the_func = locate_function(self._workspace.instance, self.addr)
            if the_func is None:
                # is it a SimProcedure?
                if self._workspace.instance.project.is_hooked(self.addr):
                    hooker = self._workspace.instance.project.hooked_by(self.addr)
                    self._function_str = "SimProcedure " + hooker.__class__.__name__.split('.')[-1]
                else:
                    self._function_str = "Unknown"
            else:
                offset = self.addr - the_func.addr
                if not the_func.name:
                    self._function_str = "%#x%+x" % (the_func.addr, offset)
                else:
                    self._function_str = "%s%+x" % (the_func.name, offset)
            # instruction
            self._instruction_str = "%s:  %s" % (self._function_str,
                                                 self._workspace.instance.get_instruction_text_at(self.addr))
            # text
            self._text = get_string_for_display(self._workspace.instance.cfg,
                                                self.addr,
                                                self._workspace.instance.project,
                                                max_size=60,
                                                )

        x = self.HORIZONTAL_PADDING
        y = self.VERTICAL_PADDING

        # definition
        self._definition_item = QGraphicsSimpleTextItem(self._definition_str, self)
        self._definition_item.setBrush(Qt.darkBlue)
        self._definition_item.setFont(Conf.symexec_font)
        self._definition_item.setPos(x, y)

        y += self._definition_item.boundingRect().height() + self.LINE_MARGIN

        # instruction
        self._instruction_item = QGraphicsSimpleTextItem(self._instruction_str, self)
        self._instruction_item.setBrush(Qt.black)
        self._instruction_item.setFont(Conf.symexec_font)
        self._instruction_item.setPos(x, y)

        x += self._instruction_item.boundingRect().width()

        # text
        if self._text:
            x += 10
            self._text_item = QGraphicsSimpleTextItem(self._text, self)
            self._text_item.setFont(Conf.symexec_font)
            self._text_item.setBrush(Qt.gray)
            self._text_item.setPos(x, y)

        # y += self._instruction_item.boundingRect().height()
        # x = self.HORIZONTAL_PADDING

    def refresh(self):
        self._update_size()

    #
    # Event handlers
    #

    def mousePressEvent(self, event): #pylint: disable=no-self-use
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        # _l.debug('QStateBlock received mouse release event')
        if event.button() == Qt.LeftButton:
            self.selected = not self.selected
            self._dep_view.redraw_graph()
            event.accept()

        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):
        # _l.debug('QStateBlock received mouse double click event')
        if event.button() == Qt.LeftButton:
            self._workspace.viz(self.addr)
            event.accept()

        super().mouseDoubleClickEvent(event)

    def hoverEnterEvent(self, event: PySide2.QtWidgets.QGraphicsSceneHoverEvent):
        self._dep_view.hover_enter_block(self)

    def hoverLeaveEvent(self, event: PySide2.QtWidgets.QGraphicsSceneHoverEvent):
        self._dep_view.hover_leave_block(self)

    def paint(self, painter, option, widget): #pylint: disable=unused-argument
        """
        Paint a state block on the scene.

        :param painter:
        :return: None
        """

        painter.setFont(Conf.symexec_font)
        normal_background = QColor(0xfa, 0xfa, 0xfa)
        selected_background = QColor(0xcc, 0xcc, 0xcc)

        # The node background
        if self.selected:
            painter.setBrush(selected_background)
        else:
            painter.setBrush(normal_background)
        painter.setPen(QPen(QColor(0xf0, 0xf0, 0xf0), 1.5))
        painter.drawRect(0, 0, self.width, self.height)

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)

    #
    # Private methods
    #

    def _update_size(self):
        width_candidates = [
            # definition string
            self._definition_item.boundingRect().width(),
            # instruction & text
            self.HORIZONTAL_PADDING * 2 + self._instruction_item.boundingRect().width() +
             ((10 + self._text_item.boundingRect().width()) if self._text_item is not None else 0),
        ]

        self._width = max(width_candidates)
        self._height = self.VERTICAL_PADDING * 2 + (self.LINE_MARGIN + self._definition_item.boundingRect().height()) * 2

        self._width = max(100, self._width)
        self._height = max(50, self._height)

        self.recalculate_size()
