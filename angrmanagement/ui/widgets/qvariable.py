from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QRectF, Qt
from PySide6.QtWidgets import QApplication, QGraphicsSimpleTextItem

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance


class QVariable(QCachedGraphicsItem):
    IDENT_LEFT_PADDING = 5
    OFFSET_LEFT_PADDING = 12

    def __init__(self, instance: Instance, disasm_view, variable, config, infodock, parent=None) -> None:
        super().__init__(parent=parent)

        # initialization
        self.instance = instance
        self.disasm_view = disasm_view
        self.variable = variable
        self._config = config
        self.infodock = infodock

        self._variable_name = None
        self._variable_name_item: QGraphicsSimpleTextItem = None
        self._variable_ident = None
        self._variable_ident_item: QGraphicsSimpleTextItem = None
        self._variable_offset = None
        self._variable_offset_item: QGraphicsSimpleTextItem = None

        self._init_widgets()

    @property
    def selected(self):
        return self.infodock.is_variable_selected(self.variable)

    #
    # Public methods
    #

    def paint(self, painter, option, widget) -> None:  # pylint: disable=unused-argument
        # Background
        if self.selected:
            painter.setPen(self._config.disasm_view_operand_select_color)
            painter.setBrush(self._config.disasm_view_operand_select_color)
            painter.drawRect(0, 0, self.width, self.height)

    def refresh(self) -> None:
        super().refresh()

        if self._variable_ident_item is not None:
            self._variable_ident_item.setVisible(self.disasm_view.show_variable_identifier)

        self._layout_items_and_update_size()

    #
    # Events
    #

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.infodock.toggle_variable_selection(
                self.variable,
                unique=QApplication.keyboardModifiers() != Qt.KeyboardModifier.ControlModifier,
            )
        else:
            super().mousePressEvent(event)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        # variable name
        self._variable_name = "" if not self.variable.name else self.variable.name
        self._variable_name_item = QGraphicsSimpleTextItem(self._variable_name, self)
        self._variable_name_item.setFont(self._config.disasm_font)
        self._variable_name_item.setBrush(self._config.disasm_view_variable_label_color)

        # variable ident
        self._variable_ident = "<%s>" % ("" if not self.variable.ident else self.variable.ident)
        self._variable_ident_item = QGraphicsSimpleTextItem(self._variable_ident, self)
        self._variable_ident_item.setFont(self._config.disasm_font)
        self._variable_ident_item.setBrush(self._config.disasm_view_variable_ident_color)
        self._variable_ident_item.setVisible(self.disasm_view.show_variable_identifier)

        # variable offset
        self._variable_offset = f"{self.variable.offset:#x}"
        self._variable_offset_item = QGraphicsSimpleTextItem(self._variable_offset, self)
        self._variable_offset_item.setFont(self._config.disasm_font)
        self._variable_offset_item.setBrush(self._config.disasm_view_variable_offset_color)

        self._layout_items_and_update_size()

    def _layout_items_and_update_size(self) -> None:
        x, y = 0, 0

        # variable name
        self._variable_name_item.setPos(x, y)
        x += self._variable_name_item.boundingRect().width() + self.IDENT_LEFT_PADDING

        if self.disasm_view.show_variable_identifier:
            # identifier
            x += self.IDENT_LEFT_PADDING
            self._variable_ident_item.setPos(x, y)
            x += self._variable_ident_item.boundingRect().width()

        # variable offset
        x += self.OFFSET_LEFT_PADDING
        self._variable_offset_item.setPos(x, y)
        x += self._variable_offset_item.boundingRect().width()

        self._width = x
        self._height = self._variable_name_item.boundingRect().height()
        self.recalculate_size()

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
