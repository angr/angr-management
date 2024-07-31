from __future__ import annotations

from typing import TYPE_CHECKING

from angr.knowledge_plugins.key_definitions.atoms import Atom, MemoryLocation, Register, SpOffset
from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QPen
from PySide6.QtWidgets import QGraphicsSimpleTextItem

from angrmanagement.config import Conf
from angrmanagement.utils import get_string_for_display, locate_function

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    import PySide6.QtWidgets
    from angr.knowledge_plugins.key_definitions.definition import Definition

    from angrmanagement.ui.views.dep_view import DependencyView


class QDepGraphBlock(QCachedGraphicsItem):
    HORIZONTAL_PADDING = 20
    VERTICAL_PADDING = 20
    LINE_MARGIN = 3

    def __init__(
        self,
        is_selected: bool,
        dep_view: DependencyView,
        definition: Definition = None,
        atom: Atom = None,
        addr: int = None,
    ) -> None:
        super().__init__()

        self._dep_view = dep_view
        self._instance = self._dep_view.instance
        self._config = Conf

        self.selected = is_selected

        # widgets
        self._definition_str: str = None
        self._definition_item: QGraphicsSimpleTextItem = None
        self._instruction_str: str = None
        self._instruction_item: QGraphicsSimpleTextItem = None
        self._function_str: str = None
        self._function_item: QGraphicsSimpleTextItem = None
        self._text: str | None = None
        self._text_item: QGraphicsSimpleTextItem | None = None

        self.definition = definition
        self.atom = atom
        self.addr = addr

        self._init_widgets()
        self._update_size()

        self.setAcceptHoverEvents(True)

    def _init_widgets(self) -> None:
        # definition
        self._definition_str = ""
        atom = self.definition.atom if self.definition is not None else self.atom
        addr_str = "unknown address" if self.addr is None else f"{self.addr:#x}"
        if isinstance(atom, Register):
            # convert it to a register name
            arch = self._instance.project.arch
            register_name = arch.translate_register_name(atom.reg_offset, size=atom.size)
            self._definition_str = f"Register {register_name} @ {addr_str}"
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                self._definition_str = f"Stack sp{atom.addr.offset:+#x} @ {addr_str}"
            elif isinstance(atom.addr, int):
                self._definition_str = f"Memory {atom.addr:#x} @ {addr_str}"

        if not self._definition_str:
            # fallback
            self._definition_str = repr(self.definition.atom)

        # function and instruction text

        if self.addr is None:
            self._function_str = "Unknown"
            self._instruction_str = "Unknown"
        else:
            # function string
            the_func = locate_function(self._instance, self.addr)
            if the_func is None:
                # is it a SimProcedure?
                if self._instance.project.is_hooked(self.addr):
                    hooker = self._instance.project.hooked_by(self.addr)
                    self._function_str = "SimProcedure " + hooker.__class__.__name__.split(".")[-1]
                else:
                    self._function_str = "Unknown"
            else:
                offset = self.addr - the_func.addr
                if not the_func.name:
                    self._function_str = f"{the_func.addr:#x}{offset:+x}"
                else:
                    self._function_str = f"{the_func.name}{offset:+x}"
            # instruction
            self._instruction_str = f"{self._function_str}:  {self._instance.get_instruction_text_at(self.addr)}"
            # text
            self._text = get_string_for_display(
                self._instance.cfg,
                self.addr,
                self._instance.project,
                max_size=60,
            )

        x = self.HORIZONTAL_PADDING
        y = self.VERTICAL_PADDING

        # definition
        self._definition_item = QGraphicsSimpleTextItem(self._definition_str, self)
        self._definition_item.setBrush(Qt.GlobalColor.darkBlue)
        self._definition_item.setFont(Conf.symexec_font)
        self._definition_item.setPos(x, y)

        y += self._definition_item.boundingRect().height() + self.LINE_MARGIN

        # instruction
        self._instruction_item = QGraphicsSimpleTextItem(self._instruction_str, self)
        self._instruction_item.setBrush(Qt.GlobalColor.black)
        self._instruction_item.setFont(Conf.symexec_font)
        self._instruction_item.setPos(x, y)

        x += self._instruction_item.boundingRect().width()

        # text
        if self._text:
            x += 10
            self._text_item = QGraphicsSimpleTextItem(self._text, self)
            self._text_item.setFont(Conf.symexec_font)
            self._text_item.setBrush(Qt.GlobalColor.gray)
            self._text_item.setPos(x, y)

        # y += self._instruction_item.boundingRect().height()
        # x = self.HORIZONTAL_PADDING

    def refresh(self) -> None:
        self._update_size()

    #
    # Event handlers
    #

    def mousePressEvent(self, event) -> None:  # pylint: disable=no-self-use
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        # _l.debug('QStateBlock received mouse release event')
        if event.button() == Qt.MouseButton.LeftButton:
            self.selected = not self.selected
            self._dep_view.redraw_graph()
            event.accept()

        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:
        # _l.debug('QStateBlock received mouse double click event')
        if event.button() == Qt.MouseButton.LeftButton:
            self._workspace.viz(self.addr)
            event.accept()

        super().mouseDoubleClickEvent(event)

    def hoverEnterEvent(self, event: PySide6.QtWidgets.QGraphicsSceneHoverEvent) -> None:
        self._dep_view.hover_enter_block(self)

    def hoverLeaveEvent(self, event: PySide6.QtWidgets.QGraphicsSceneHoverEvent) -> None:
        self._dep_view.hover_leave_block()

    def paint(self, painter, option, widget) -> None:  # pylint: disable=unused-argument
        """
        Paint a state block on the scene.

        :param painter:
        :return: None
        """

        painter.setFont(Conf.symexec_font)
        normal_background = QColor(0xFA, 0xFA, 0xFA)
        selected_background = QColor(0xCC, 0xCC, 0xCC)

        # The node background
        if self.selected:
            painter.setBrush(selected_background)
        else:
            painter.setBrush(normal_background)
        painter.setPen(QPen(QColor(0xF0, 0xF0, 0xF0), 1.5))
        painter.drawRect(0, 0, self.width, self.height)

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)

    #
    # Private methods
    #

    def _update_size(self) -> None:
        width_candidates = [
            # definition string
            self._definition_item.boundingRect().width(),
            # instruction & text
            self.HORIZONTAL_PADDING * 2
            + self._instruction_item.boundingRect().width()
            + ((10 + self._text_item.boundingRect().width()) if self._text_item is not None else 0),
        ]

        self._width = max(width_candidates)
        self._height = (
            self.VERTICAL_PADDING * 2 + (self.LINE_MARGIN + self._definition_item.boundingRect().height()) * 2
        )

        self._width = max(100, self._width)
        self._height = max(50, self._height)

        self.recalculate_size()
