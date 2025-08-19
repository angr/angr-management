from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pyvex

try:
    import pypcode
except ImportError:
    pypcode = None

from PySide6.QtGui import QTextCharFormat

from angrmanagement.config import Conf

from .base_objects import BlockTreeNode

if TYPE_CHECKING:
    from archinfo import RegisterOffset, TmpVar


OBJ_CLASS_TO_QBLOCKCODE_CLASS = {}


class QIROpObj(BlockTreeNode):
    """
    Renders a Lifter IR object
    """

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_ir_default_color)
        return fmt

    def __init__(self, obj: Any, *args, irobj=None, **kwargs) -> None:
        self.irobj = irobj or obj
        super().__init__(obj, *args, **kwargs)

    def create_subobjs(self, obj) -> None:
        self.add_irobj(obj.obj)

    def add_irobj(self, obj) -> None:
        subobjcls = OBJ_CLASS_TO_QBLOCKCODE_CLASS.get(type(obj), QIROpTextObj)
        subobj = subobjcls(obj, self.infodock, parent=self, options=self.options, irobj=self.irobj)
        self._add_subobj(subobj)


class QIROpTextObj(QIROpObj):
    """
    Renders a Lifter IR object using the object's __str__, or as hexadecimal
    if an integer type.
    """

    def create_subobjs(self, obj: Any) -> None:
        if isinstance(obj, int):
            self.add_text(f"{obj:#x}")
        else:
            self.add_text(str(obj))


class QIrOpPcodeOp(QIROpTextObj):
    """
    Renders a P-code op.
    """

    def create_subobjs(self, obj: pypcode.PcodeOp) -> None:  # type:ignore[reportInvalidTypeForm]
        self.add_text(pypcode.PcodePrettyPrinter.fmt_op(obj))  # type:ignore


if pypcode:
    OBJ_CLASS_TO_QBLOCKCODE_CLASS.update({pypcode.PcodeOp: QIrOpPcodeOp})


class QIROpVexConstObj(QIROpTextObj):
    """
    Renders a pyvex.expr.Const
    """

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_operand_constant_color)
        return fmt

    def should_highlight(self) -> bool:
        return (
            isinstance(self.infodock.selected_block_tree_node, QIROpVexConstObj)
            and self.infodock.selected_block_tree_node.obj._con == self.obj._con
        )


class VexIRTmpWrapper:
    """
    A wrapper class for VEX temps
    """

    __slots__ = (
        "tid",
        "reg_name",
    )

    tid: TmpVar
    reg_name: str | None

    def __init__(self, tid: TmpVar, reg_name: str | None = None) -> None:
        self.tid = tid
        self.reg_name = reg_name or (f"t{self.tid}")

    def __str__(self) -> str:
        return self.reg_name if self.reg_name is not None else "None"


class VexIRRegWrapper:
    """
    A wrapper class for VEX registers
    """

    __slots__ = (
        "offset",
        "reg_name",
    )

    offset: RegisterOffset
    reg_name: str | None

    def __init__(self, offset: RegisterOffset, reg_name: str | None = None) -> None:
        self.offset = offset
        self.reg_name = reg_name or (f"offset={self.offset}")

    def __str__(self) -> str:
        return self.reg_name if self.reg_name is not None else "None"


class QIROpVexWrTmpObj(QIROpTextObj):
    """
    Renders a pyvex.stmt.WrTmp
    """

    def create_subobjs(self, obj: pyvex.stmt.WrTmp) -> None:
        irsb = self.irobj.irsb
        self.add_irobj(VexIRTmpWrapper(obj.tmp))
        self.add_text(" = ")
        if isinstance(obj.data, pyvex.expr.Get):
            reg_name = irsb.arch.translate_register_name(obj.data.offset, obj.data.result_size(irsb.tyenv) // 8)
            self.add_irobj(VexIRRegWrapper(obj.data.offset, reg_name))  # type:ignore
        else:
            self.add_irobj(obj.data)


class QIROpVexRdTmpObj(QIROpTextObj):
    """
    Renders a pyvex.expr.RdTmp
    """

    def create_subobjs(self, obj: pyvex.expr.RdTmp) -> None:
        self.add_irobj(VexIRTmpWrapper(obj.tmp))


class QIROpVexTmpObj(QIROpTextObj):
    """
    Renders a VEX temporary
    """

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_operand_color)
        return fmt

    def should_highlight(self) -> bool:
        return (
            isinstance(self.infodock.selected_block_tree_node, QIROpVexTmpObj)
            and self.infodock.selected_block_tree_node.obj.tid == self.obj.tid
        )


class QIROpVexRegObj(QIROpTextObj):
    """
    Renders a VEX register
    """

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_operand_color)
        return fmt

    def should_highlight(self) -> bool:
        return (
            isinstance(self.infodock.selected_block_tree_node, QIROpVexRegObj)
            and self.infodock.selected_block_tree_node.obj.offset == self.obj.offset
        )


class QIROpVexStoreObj(QIROpTextObj):
    """
    Renders a pyvex.stmt.Store
    """

    def create_subobjs(self, obj: pyvex.stmt.Store) -> None:
        # "ST%s(%s) = %s" % (self.endness[-2:].lower(), self.addr, self.data)
        self.add_text(f"ST{obj.endness[-2:].lower()}(")
        self.add_irobj(obj.addr)
        self.add_text(") = ")
        self.add_irobj(obj.data)


class QIROpVexLoadObj(QIROpTextObj):
    """
    Renders a pyvex.expr.Load
    """

    def create_subobjs(self, obj: pyvex.expr.Load) -> None:
        self.add_text(f"LD{obj.end[-2:].lower()}:{obj.ty[4:]}(")
        self.add_irobj(obj.addr)
        self.add_text(")")


class QIROpVexPutObj(QIROpTextObj):
    """
    Renders a pyvex.stmt.Put
    """

    def create_subobjs(self, obj: pyvex.stmt.Put) -> None:
        irsb = self.irobj.irsb
        reg_name = irsb.arch.translate_register_name(obj.offset, obj.data.result_size(irsb.tyenv) // 8)
        self.add_text("PUT(")
        self.add_irobj(VexIRRegWrapper(obj.offset, reg_name))  # type:ignore
        self.add_text(") = ")
        self.add_irobj(obj.data)


class QIROpVexExitObj(QIROpTextObj):
    """
    Renders a pyvex.stmt.Exit
    """

    def create_subobjs(self, obj: pyvex.stmt.Exit) -> None:
        irsb = self.irobj.irsb
        arch = irsb.arch
        reg_name = arch.translate_register_name(irsb.offsIP, arch.bits // 8)
        self.add_text("if (")
        self.add_irobj(obj.guard)
        self.add_text(") { PUT(")
        self.add_irobj(VexIRRegWrapper(obj.offsIP, reg_name))  # type:ignore
        self.add_text(") = ")
        self.add_irobj(obj.dst.value)
        self.add_text("; ")
        self.add_irobj(obj.jumpkind)
        self.add_text(" }")


class QIROpVexBinopObj(QIROpTextObj):
    """
    Renders a pyvex.expr.Binop
    """

    def create_subobjs(self, obj: pyvex.expr.Binop) -> None:
        self.add_text(obj.op[4:])
        self.add_text("(")
        self.add_irobj(obj.args[0])
        self.add_text(",")
        self.add_irobj(obj.args[1])
        self.add_text(")")


class QIROpVexUnopObj(QIROpTextObj):
    """
    Renders a pyvex.expr.Unop
    """

    def create_subobjs(self, obj: pyvex.expr.Unop) -> None:
        self.add_text(obj.op[4:])
        self.add_text("(")
        self.add_irobj(obj.args[0])
        self.add_text(")")


OBJ_CLASS_TO_QBLOCKCODE_CLASS.update(
    {
        pyvex.stmt.WrTmp: QIROpVexWrTmpObj,
        pyvex.expr.RdTmp: QIROpVexRdTmpObj,
        pyvex.stmt.Store: QIROpVexStoreObj,
        pyvex.expr.Load: QIROpVexLoadObj,
        pyvex.stmt.Put: QIROpVexPutObj,
        pyvex.stmt.Exit: QIROpVexExitObj,
        pyvex.expr.Const: QIROpVexConstObj,
        pyvex.expr.Binop: QIROpVexBinopObj,
        pyvex.expr.Unop: QIROpVexUnopObj,
        VexIRTmpWrapper: QIROpVexTmpObj,
        VexIRRegWrapper: QIROpVexRegObj,
    }
)
