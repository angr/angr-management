from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angr import ailment
from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCharFormat

from angrmanagement.config import Conf
from angrmanagement.utils import string_at_addr

from .base_objects import BlockTreeNode

if TYPE_CHECKING:
    from PySide6.QtWidgets import QGraphicsSceneMouseEvent

    from angrmanagement.data.instance import Instance


class QAilObj(BlockTreeNode):
    """
    Renders an AIL object
    """

    def __init__(self, obj: Any, instance: Instance, *args, stmt=None, **kwargs) -> None:
        self.stmt = stmt or obj
        self.instance = instance
        super().__init__(obj, *args, **kwargs)

    def create_subobjs(self, obj: Any) -> None:
        self.add_ailobj(obj)

    def add_ailobj(self, obj: Any) -> None:
        """
        Map appropriate AIL type to the display type
        """
        subobjcls = {
            ailment.statement.Assignment: QAilAssignmentObj,
            ailment.statement.Store: QAilStoreObj,
            ailment.statement.Jump: QAilJumpObj,
            ailment.statement.ConditionalJump: QAilConditionalJumpObj,
            ailment.statement.Return: QAilReturnObj,
            ailment.statement.Call: QAilCallObj,
            ailment.expression.Const: QAilConstObj,
            ailment.expression.Tmp: QAilTmpObj,
            ailment.expression.Register: QAilRegisterObj,
            ailment.expression.UnaryOp: QAilUnaryOpObj,
            ailment.expression.BinaryOp: QAilBinaryOpObj,
            ailment.expression.Convert: QAilConvertObj,
            ailment.expression.Load: QAilLoadObj,
        }.get(type(obj), QAilTextObj)
        subobj = subobjcls(obj, self.instance, self.infodock, parent=self, options=self.options, stmt=self.stmt)
        self._add_subobj(subobj)

    @property
    def should_highlight_line(self):
        ail_obj_ins_addr = getattr(self.obj, "ins_addr", None)
        if ail_obj_ins_addr is not None and self.infodock.is_instruction_selected(ail_obj_ins_addr):
            return True
        return super().should_highlight_line

    def mousePressEvent(self, event: QGraphicsSceneMouseEvent) -> None:  # pylint: disable=unused-argument
        super().mousePressEvent(event)
        button = event.button()
        if button == Qt.MouseButton.LeftButton:
            ail_obj_ins_addr = getattr(self.obj, "ins_addr", None)
            if ail_obj_ins_addr is not None:
                self.infodock.select_instruction(ail_obj_ins_addr)


class QAilTextObj(QAilObj):
    """
    Renders an AIL object via __str__
    """

    def create_subobjs(self, obj: Any) -> None:
        self.add_text(str(obj))


class QAilAssignmentObj(QAilTextObj):
    """
    Renders an ailment.statement.Assignment
    """

    def create_subobjs(self, obj: ailment.statement.Assignment) -> None:
        self.add_ailobj(obj.dst)
        self.add_text(" = ")
        self.add_ailobj(obj.src)


class QAilStoreObj(QAilTextObj):
    """
    Renders an ailment.statement.Store
    """

    def create_subobjs(self, obj: ailment.statement.Store) -> None:
        if obj.variable is None or not self.options.show_variables:
            self.add_text("*(")
            self.add_ailobj(obj.addr)
            self.add_text(") = ")
            self.add_ailobj(obj.data)
        else:
            self.add_variable(obj.variable)
            self.add_text(" = ")
            self.add_ailobj(obj.data)


class QAilJumpObj(QAilTextObj):
    """
    Renders an ailment.statement.Jump
    """

    def create_subobjs(self, obj: ailment.statement.Jump) -> None:
        self.add_text("goto ")
        self.add_ailobj(obj.target)


class QAilConditionalJumpObj(QAilTextObj):
    """
    Renders an ailment.statement.ConditionalJump
    """

    def create_subobjs(self, obj: ailment.statement.ConditionalJump) -> None:
        self.add_text("if ")
        self.add_ailobj(obj.condition)

        if self.options.show_conditional_jump_targets:
            self.add_text(" goto ")
            self.add_ailobj(obj.true_target)
            self.add_text(" else goto ")
            self.add_ailobj(obj.false_target)


class QAilReturnObj(QAilTextObj):
    """
    Renders an ailment.statement.Return
    """

    def create_subobjs(self, obj: ailment.statement.Return) -> None:
        self.add_text("return ")
        for expr in obj.ret_exprs:
            self.add_ailobj(expr)


class QAilCallObj(QAilTextObj):
    """
    Renders an ailment.statement.Call
    """

    def create_subobjs(self, obj: ailment.statement.Call) -> None:
        if obj.ret_expr is not None and self.stmt is self.obj:
            self.add_ailobj(obj.ret_expr)
            self.add_text(" = ")
        self.add_ailobj(obj.target)
        self.add_text("(")
        if obj.args:
            for i, arg in enumerate(obj.args):
                if i > 0:
                    self.add_text(", ")
                self.add_ailobj(arg)
        self.add_text(")")


class QAilConstObj(QAilTextObj):
    """
    Renders an ailment.expression.Const
    """

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_operand_constant_color)
        return fmt

    def create_subobjs(self, obj: ailment.expression.Const) -> None:
        if not isinstance(obj.value, int):
            return

        # take care of labels first
        kb = self.infodock.disasm_view.disasm.kb
        if obj.value in kb.labels:
            self.add_text(kb.labels[obj.value])
            return

        data_str = string_at_addr(
            self.instance.cfg,
            obj.value,
            self.instance.project,  # type:ignore
        )
        if data_str:
            self.add_text(data_str)
        else:
            self.add_text(f"{obj.value:#x}")

    def should_highlight(self) -> bool:
        return (
            isinstance(self.infodock.selected_qblock_code_obj, QAilConstObj)
            and self.infodock.selected_qblock_code_obj.obj.value == self.obj.value
        )

    def mouseDoubleClickEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        super().mouseDoubleClickEvent(event)
        button = event.button()
        if button == Qt.MouseButton.LeftButton:
            src_ins_addr = getattr(self.stmt, "ins_addr", None)
            self.infodock.disasm_view.jump_to(self.obj.value, src_ins_addr=src_ins_addr, use_animation=True)


class QAilTmpObj(QAilTextObj):
    """
    Renders an ailment.expression.Tmp
    """

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_operand_color)
        return fmt


class QAilRegisterObj(QAilTextObj):
    """
    Renders an ailment.expression.Register
    """

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_operand_color)
        return fmt

    def create_subobjs(self, obj: ailment.expression.Register) -> None:
        if obj.variable is not None and self.options.show_variables:
            self.add_variable(obj.variable)
        else:
            s = f"{obj.reg_name}" if hasattr(obj, "reg_name") else f"reg_{obj.reg_offset}<{obj.bits // 8}>"
            self.add_text(s)

    def should_highlight(self) -> bool:
        sel = self.infodock.selected_qblock_code_obj
        return isinstance(sel, QAilRegisterObj) and sel.obj == self.obj


class QAilUnaryOpObj(QAilTextObj):
    """
    Renders an ailment.expression.UnaryOp
    """

    def create_subobjs(self, obj: ailment.expression.UnaryOp) -> None:
        self.add_text("(")
        self.add_text(obj.op + " ")
        self.add_ailobj(obj.operand)
        self.add_text(")")


class QAilBinaryOpObj(QAilTextObj):
    """
    Renders an ailment.expression.BinaryOp
    """

    def create_subobjs(self, obj: ailment.expression.BinaryOp) -> None:
        self.add_text("(")
        self.add_ailobj(obj.operands[0])
        verbose_op = obj.OPSTR_MAP.get(obj.verbose_op, obj.verbose_op)
        if verbose_op is None:
            verbose_op = "unknown_op"
        self.add_text(" " + verbose_op + " ")
        self.add_ailobj(obj.operands[1])
        self.add_text(")")


class QAilConvertObj(QAilTextObj):
    """
    Renders an ailment.expression.Convert
    """

    def create_subobjs(self, obj: ailment.expression.Convert) -> None:
        self.add_text(f"Conv({obj.from_bits}->{obj.to_bits}, ")
        self.add_ailobj(obj.operand)
        self.add_text(")")


class QAilLoadObj(QAilTextObj):
    """
    Renders an ailment.expression.Load
    """

    def create_subobjs(self, obj: ailment.expression.Load) -> None:
        if obj.variable is not None and self.options.show_variables:
            self.add_variable(obj.variable)
        else:
            self.add_text("*(")
            self.add_ailobj(obj.addr)
            self.add_text(")")
