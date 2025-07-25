from __future__ import annotations

from typing import TYPE_CHECKING

from angr.calling_conventions import SimRegArg
from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QCursor, QPainter
from PySide6.QtWidgets import QApplication, QGraphicsSimpleTextItem

from angrmanagement.config import Conf
from angrmanagement.utils.func import type2str

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angr.sim_type import SimTypeFunction


class QFunctionHeader(QCachedGraphicsItem):
    """
    Function header item in the disassembly view.

    A function header item includes the following items:
    - Function name, or demangled function name if available
    - Original function name if there is a demangled function name available
    - Function prototype: return type, argument type, and arguments
    - Calling convention
    - A list of arguments in terms of registers and memory allocations
    - Number of callers
    - Number of callees
    """

    TOP_MARGIN_LINES = 1
    BOTTOM_MARGIN_LINES = 1

    def __init__(
        self,
        addr: int,
        name: str,
        demangled_name: str | None,
        prototype,
        args,
        config,
        disasm_view,
        infodock,
        parent=None,
    ) -> None:
        super().__init__(parent=parent)

        self.addr = addr
        self.name = name
        self.demangled_name = demangled_name
        self.prototype: SimTypeFunction = prototype
        self.args = args
        self.infodock = infodock

        self._width = 0
        self._height = 0

        self._config = config
        self._disasm_view = disasm_view

        self._return_type_width = None
        self._arg_str_list = None
        self._args_str = None

        # function name
        self._function_name_item: QGraphicsSimpleTextItem | None = None
        # demangled function name
        self._demangled_function_name_item: QGraphicsSimpleTextItem | None = None
        # function prototype
        self._proto_left_paren_item: QGraphicsSimpleTextItem | None = None
        self._proto_return_type_item: QGraphicsSimpleTextItem | None = None
        self._proto_param_items: list[
            tuple[QGraphicsSimpleTextItem, QGraphicsSimpleTextItem, QGraphicsSimpleTextItem | None]
        ] = []
        self._proto_right_paren_item: QGraphicsSimpleTextItem | None = None
        # arguments
        self._arg_items: list[QGraphicsSimpleTextItem] = []

        self._init_widgets()

    def setVisible(self, visible):
        if self._function_name_item is not None:
            self._function_name_item.setVisible(visible)
        if self._demangled_function_name_item is not None:
            self._demangled_function_name_item.setVisible(visible)
        if self._proto_return_type_item is not None:
            self._proto_return_type_item.setVisible(visible)
        if self._proto_left_paren_item is not None:
            self._proto_left_paren_item.setVisible(visible)
        for param_type, param_name, comma_item in self._proto_param_items:
            param_type.setVisible(visible)
            param_name.setVisible(visible)
            if comma_item is not None:
                comma_item.setVisible(visible)
        if self._proto_right_paren_item is not None:
            self._proto_right_paren_item.setVisible(visible)
        for arg in self._arg_items:
            arg.setVisible(visible)

    def refresh(self) -> None:
        pass

    def paint(self, painter, option, widget=None) -> None:
        painter.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform)

        if self.infodock.is_label_selected(self.addr):
            highlight_color = Conf.disasm_view_label_highlight_color
            painter.setBrush(highlight_color)
            painter.setPen(highlight_color)
            painter.drawRect(0, 0, self.width, self.height)

    #
    # Event handlers
    #

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.infodock.select_label(self.addr)
        elif (
            event.button() == Qt.MouseButton.RightButton
            and QApplication.keyboardModifiers() == Qt.KeyboardModifier.NoModifier
        ):
            if self.addr not in self.infodock.selected_labels:
                self.infodock.select_label(self.addr)
            self._disasm_view.label_context_menu(self.addr, QCursor.pos())

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        if self.args is not None:
            self._arg_str_list = []
            for arg in self.args:
                if isinstance(arg, SimRegArg):
                    self._arg_str_list.append(arg.reg_name)
                else:
                    self._arg_str_list.append(str(arg))

            self._args_str = "Args: ({})".format(", ".join(self._arg_str_list))
        else:
            self._args_str = ""

        #
        # function name
        #

        if self.demangled_name and self.demangled_name != self.name:
            self._demangled_function_name_item = QGraphicsSimpleTextItem(self.demangled_name, self)
            self._demangled_function_name_item.setFont(self._config.disasm_font)
            self._demangled_function_name_item.setBrush(self._config.disasm_view_function_color)
        self._function_name_item = QGraphicsSimpleTextItem(self.name, self)
        self._function_name_item.setFont(self._config.disasm_font)
        self._function_name_item.setBrush(self._config.disasm_view_function_color)

        #
        # function prototype
        #

        if self.prototype is not None:
            # function return type
            rt = type2str(self.prototype.returnty)
            self._proto_return_type_item = QGraphicsSimpleTextItem(rt, self)
            self._proto_return_type_item.setFont(self._config.disasm_font)
            self._proto_return_type_item.setBrush(self._config.disasm_view_function_arg_type_color)

            # left parenthesis
            self._proto_left_paren_item = QGraphicsSimpleTextItem("(", self)
            self._proto_left_paren_item.setFont(self._config.disasm_font)
            self._proto_left_paren_item.setBrush(self._config.disasm_view_function_color)

            # function parameters
            self._proto_param_items = []
            for i, arg_type in enumerate(self.prototype.args):
                type_str = type2str(arg_type)
                type_item = QGraphicsSimpleTextItem(type_str, self)
                type_item.setFont(self._config.disasm_font)
                type_item.setBrush(self._config.disasm_view_function_arg_type_color)

                if self.prototype.arg_names and i < len(self.prototype.arg_names):
                    param_name = self.prototype.arg_names[i]
                else:
                    param_name = f"arg_{i}"
                param_item = QGraphicsSimpleTextItem(param_name, self)
                param_item.setFont(self._config.disasm_font)
                param_item.setBrush(self._config.disasm_view_function_arg_name_color)
                if i < len(self.prototype.args) - 1:
                    comma_item = QGraphicsSimpleTextItem(",", self)
                    comma_item.setFont(self._config.disasm_font)
                    comma_item.setBrush(self._config.disasm_view_function_color)
                else:
                    comma_item = None
                self._proto_param_items.append((type_item, param_item, comma_item))

            # right parenthesis
            self._proto_right_paren_item = QGraphicsSimpleTextItem(")", self)
            self._proto_right_paren_item.setFont(self._config.disasm_font)
            self._proto_right_paren_item.setBrush(self._config.disasm_view_function_color)

        # arguments
        if self._arg_str_list is not None:
            self._arg_items = []
            for arg_str in self._arg_str_list:
                item = QGraphicsSimpleTextItem(arg_str, self)
                item.setFont(self._config.disasm_font)
                item.setBrush(self._config.disasm_view_function_color)
                self._arg_items.append(item)

        self._layout_items_and_update_size()

    def _layout_items_and_update_size(self) -> None:
        x, y = 0, self.TOP_MARGIN_LINES * Conf.disasm_font_height

        if self.prototype is None:
            # function name only
            if self._demangled_function_name_item is not None:
                # demangled function name
                self._demangled_function_name_item.setPos(x, y)
                height = self._demangled_function_name_item.boundingRect().height()
                y += height
                x = 0
            # normal function name
            self._function_name_item.setPos(x, y)
            height = self._function_name_item.boundingRect().height()
            y += height
        else:
            # prototype and function name
            self._proto_return_type_item.setPos(x, y)
            x += self._proto_return_type_item.boundingRect().width() + Conf.disasm_font_width

            # function name
            if self._demangled_function_name_item is not None:
                self._demangled_function_name_item.setPos(x, y)
                x += self._demangled_function_name_item.boundingRect().width()
            else:
                self._function_name_item.setPos(x, y)
                x += self._function_name_item.boundingRect().width()

            # left parenthesis
            self._proto_left_paren_item.setPos(x, y)
            x += self._proto_left_paren_item.boundingRect().width()
            # parameters
            for type_item, param_item, comma_item in self._proto_param_items:
                # param type
                type_item.setPos(x, y)
                x += type_item.boundingRect().width() + Conf.disasm_font_width
                # name
                param_item.setPos(x, y)
                x += param_item.boundingRect().width()
                # comma
                if comma_item is not None:
                    comma_item.setPos(x, y)
                    x += comma_item.boundingRect().width() + Conf.disasm_font_width
            # right parenthesis
            self._proto_right_paren_item.setPos(x, y)
            x += self._proto_right_paren_item.boundingRect().width()
            height = self._function_name_item.boundingRect().height()
            y += height

        max_x = x

        if self._arg_items:
            # new line
            x = 0
            y += height
            # arguments
            for arg_item in self._arg_items:
                arg_item.setPos(x, y)
                y += arg_item.boundingRect().height()

        y += self.BOTTOM_MARGIN_LINES * Conf.disasm_font_height

        max_x = max(x, max_x)
        self._width = max_x
        self._height = y
        self.recalculate_size()

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
