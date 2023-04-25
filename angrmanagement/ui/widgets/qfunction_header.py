from typing import TYPE_CHECKING, Optional

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
    def __init__(self, addr, name, prototype, args, config, disasm_view, workspace, infodock, parent=None):
        super().__init__(parent=parent)

        self.workspace = workspace
        self.addr = addr
        self.name = name
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

        self._function_name_item: QGraphicsSimpleTextItem = None
        self._args_str_item: QGraphicsSimpleTextItem = None
        self._prototype_arg_item: Optional[QGraphicsSimpleTextItem] = None

        self._init_widgets()

    def refresh(self):
        pass

    def paint(self, painter, option, widget):
        painter.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform)

        if self.infodock.is_label_selected(self.addr):
            highlight_color = Conf.disasm_view_label_highlight_color
            painter.setBrush(highlight_color)
            painter.setPen(highlight_color)
            painter.drawRect(0, 0, self.width, self.height)

    #
    # Event handlers
    #

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.infodock.select_label(self.addr)
        elif event.button() == Qt.RightButton and QApplication.keyboardModifiers() == Qt.NoModifier:
            if self.addr not in self.infodock.selected_labels:
                self.infodock.select_label(self.addr)
            self._disasm_view.label_context_menu(self.addr, QCursor.pos())

    #
    # Private methods
    #

    def _init_widgets(self):
        if self.args is not None:
            self._arg_str_list = []
            for arg in self.args:
                if isinstance(arg, SimRegArg):
                    self._arg_str_list.append(arg.reg_name)
                else:
                    self._arg_str_list.append(str(arg))

            self._args_str = "Args: (%s)" % (", ".join(self._arg_str_list))
        else:
            self._args_str = ""

        #
        # prototype
        #

        if self.prototype is None:
            # Just print the function name
            self._function_name_item = QGraphicsSimpleTextItem(self.name, self)
            self._function_name_item.setFont(self._config.code_font)
            self._function_name_item.setBrush(self._config.disasm_view_function_color)

        else:
            # print the prototype

            proto_str = ""

            # Type of the return value
            rt = type2str(self.prototype.returnty)
            proto_str += rt

            # space
            proto_str += " "

            # function name
            proto_str += self.name

            # left parenthesis
            proto_str += "("

            # arguments
            for i, arg_type in enumerate(self.prototype.args):
                type_str = type2str(arg_type)
                proto_str += type_str + " "

                if self.prototype.arg_names and i < len(self.prototype.arg_names):
                    arg_name = self.prototype.arg_names[i]
                else:
                    arg_name = "arg_%d" % i
                proto_str += arg_name

                if i < len(self.prototype.args) - 1:
                    # splitter
                    proto_str += ", "

            # right parenthesis
            proto_str += ")"

            self._prototype_arg_item = QGraphicsSimpleTextItem(proto_str, self)
            self._prototype_arg_item.setFont(self._config.code_font)
            self._prototype_arg_item.setBrush(self._config.disasm_view_function_color)

        # arguments
        if self._arg_str_list is not None:
            s = "Args: (" + ", ".join(self._arg_str_list) + ")"
            self._args_str_item = QGraphicsSimpleTextItem(s, self)
            self._args_str_item.setFont(self._config.code_font)
            self._args_str_item.setBrush(self._config.disasm_view_function_color)

        self._layout_items_and_update_size()

    def _layout_items_and_update_size(self):
        x, y = 0, 0

        if self._function_name_item is not None:
            # function anme
            self._function_name_item.setPos(x, y)
            x += self._function_name_item.boundingRect().width()
            height = self._function_name_item.boundingRect().height()
        elif self._prototype_arg_item is not None:
            # prototype
            self._prototype_arg_item.setPos(x, y)
            x += self._prototype_arg_item.boundingRect().width()
            height = self._prototype_arg_item.boundingRect().height()
        else:
            height = 0

        # new line
        max_x = x
        x = 0
        y += height

        # arguments
        if self._args_str_item is not None:
            self._args_str_item.setPos(x, y)
            x += self._args_str_item.boundingRect().width()
            y += self._args_str_item.boundingRect().height()

        max_x = max(x, max_x)
        self._width = max_x
        self._height = y
        self.recalculate_size()

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
