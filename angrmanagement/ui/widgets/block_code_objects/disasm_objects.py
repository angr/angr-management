from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angr.calling_conventions import SimRegArg
from PySide6.QtCore import Qt
from PySide6.QtGui import QCursor, QTextCharFormat
from PySide6.QtWidgets import QApplication, QGraphicsSceneMouseEvent

from angrmanagement.config import Conf
from angrmanagement.utils.func import type2str

from .base_objects import QBlockCodeObj

if TYPE_CHECKING:
    from angr.sim_type import SimTypeFunction


class QFunctionHeaderFuncNameItem(QBlockCodeObj):
    def __init__(self, addr: int, name: str, infodock, parent=None):
        self.addr = addr
        self.name = name
        super().__init__(self, infodock, parent)

    def create_subobjs(self, obj) -> None:
        self.add_text(self.name)

    @property
    def selection_key(self) -> Any:
        return "func_name", self.addr

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setFont(Conf.disasm_font)
        fmt.setForeground(Conf.disasm_view_function_color)
        return fmt


class QFunctionHeaderFuncTypeItem(QBlockCodeObj):
    def __init__(self, addr: int, arg_id: int, type_str: str, infodock, parent=None):
        self.addr = addr
        self.arg_id = arg_id
        self.type_str = type_str
        super().__init__(self, infodock, parent)

    def create_subobjs(self, obj) -> None:
        self.add_text(self.type_str)

    @property
    def selection_key(self) -> Any:
        return ("param_type", self.addr, self.arg_id) if self.arg_id >= 0 else ("return_type", 0)

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setFont(Conf.disasm_font)
        fmt.setForeground(Conf.disasm_view_function_arg_type_color)
        return fmt


class QFunctionHeaderFuncParamItem(QBlockCodeObj):
    def __init__(self, addr: int, arg_id: int, param_str: str, infodock, parent=None):
        self.addr = addr
        self.arg_id = arg_id
        self.param_str = param_str
        super().__init__(self, infodock, parent)

    def create_subobjs(self, obj) -> None:
        self.add_text(self.param_str)

    @property
    def selection_key(self) -> Any:
        return "param_item", self.addr, self.arg_id

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setFont(Conf.disasm_font)
        fmt.setForeground(Conf.disasm_view_function_arg_name_color)
        return fmt


class QFunctionHeaderFuncArgItem(QBlockCodeObj):
    def __init__(self, addr: int, arg_id: int, arg_str: str, infodock, parent=None):
        self.addr = addr
        self.arg_id = arg_id
        self.arg_str = arg_str
        super().__init__(self, infodock, parent)

    def create_subobjs(self, obj) -> None:
        self.add_text(self.arg_str)

    @property
    def selection_key(self) -> Any:
        return "arg_item", self.addr, self.arg_id

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setFont(Conf.disasm_font)
        fmt.setForeground(Conf.disasm_view_function_arg_name_color)
        return fmt


class QFunctionHeader(QBlockCodeObj):
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

    def __init__(
        self,
        addr: int,
        name: str,
        demangled_name: str | None,
        prototype,
        args,
        infodock,
        parent=None,
        options=None,
    ) -> None:
        self.addr = addr
        self.name = name
        self.demangled_name = demangled_name
        self.prototype: SimTypeFunction = prototype
        self.args = args

        self._arg_str_list = None

        self._init_items()

        super().__init__(
            None, infodock, parent, options=options, show_address=False, top_margin_lines=1, bottom_margin_lines=1
        )

    def create_subobjs(self, obj) -> None:
        #
        # function name
        #

        if self.demangled_name and self.demangled_name != self.name:
            sub_obj = QFunctionHeaderFuncNameItem(self.addr, self.demangled_name, self.infodock, self)
            self._add_subobj(sub_obj)
            self.add_newline()

        #
        # Function prototype (including function name)
        #

        if self.prototype is None:
            # function name
            sub_obj = QFunctionHeaderFuncNameItem(self.addr, self.name, self.infodock, self)
            self._add_subobj(sub_obj)
            self.add_text("()")

        else:
            # return type
            rt = type2str(self.prototype.returnty)
            sub_obj = QFunctionHeaderFuncTypeItem(self.addr, -1, rt, self.infodock, self)
            self._add_subobj(sub_obj)
            self.add_text(" ")

            # function name
            sub_obj = QFunctionHeaderFuncNameItem(self.addr, self.name, self.infodock, self)
            self._add_subobj(sub_obj)

            self.add_text("(")

            # parameters
            for i, arg_type in enumerate(self.prototype.args):
                type_str = type2str(arg_type)
                sub_obj = QFunctionHeaderFuncTypeItem(self.addr, i, type_str, self.infodock, self)
                self._add_subobj(sub_obj)
                self.add_text(" ")

                if self.prototype.arg_names and i < len(self.prototype.arg_names):
                    param_name = self.prototype.arg_names[i]
                else:
                    param_name = f"arg_{i}"
                sub_obj = QFunctionHeaderFuncParamItem(self.addr, i, param_name, self.infodock, self)
                self._add_subobj(sub_obj)

                if i < len(self.prototype.args) - 1:
                    self.add_text(", ")

            self.add_text(")")
        self.add_newline(2)

        # arguments
        if self._arg_str_list is not None:
            for i, arg_str in enumerate(self._arg_str_list):
                sub_obj = QFunctionHeaderFuncArgItem(self.addr, i, arg_str, self.infodock, self)
                self.add_text(f"arg_{i} @ ")
                self._add_subobj(sub_obj)
                self.add_newline()

    def should_highlight(self) -> bool:
        #  we don't highlight the entire function header
        return False

    #
    # Event handlers
    #

    def mousePressEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        # do not handle left click events; individual items will handle them
        if (
            event.button() == Qt.MouseButton.RightButton
            and QApplication.keyboardModifiers() == Qt.KeyboardModifier.NoModifier
        ):
            if self.addr not in self.infodock.selected_labels:
                self.infodock.select_label(self.addr)
            self.infodock.disasm_view.label_context_menu(self.addr, QCursor.pos())

    #
    # Private methods
    #

    def _init_items(self) -> None:
        if self.args is not None:
            self._arg_str_list = []
            for arg in self.args:
                if isinstance(arg, SimRegArg):
                    self._arg_str_list.append(arg.reg_name)
                else:
                    self._arg_str_list.append(str(arg))
