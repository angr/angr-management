from typing import Any, Sequence, Optional, Tuple

from PySide2.QtGui import QPainter, QTextDocument, QTextCursor, QTextCharFormat, QFont, QMouseEvent
from PySide2.QtCore import Qt, QPointF, QRectF, QObject
from PySide2.QtWidgets import QGraphicsSimpleTextItem

import ailment
import pyvex
from archinfo import RegisterOffset, TmpVar

from ...config import Conf, ConfigurationManager
from ...logic.disassembly.info_dock import InfoDock
from ...utils import string_at_addr
from .qgraph_object import QCachedGraphicsItem


class QBlockCodeOptions:
    """
    Various options to control display of QBlockCodeObj's
    """
    show_conditional_jump_targets: bool = True
    show_variables: bool = True
    show_variable_identifiers: bool = True


class QBlockCodeObj(QObject):
    """
    Renders a generic "code" object and handles display related events.
    Instances of this class mirror an AST structure, with references in the
    `obj` property to whatever object should be displayed. Leaf nodes will add
    text to the display document during render, which is handled at the top
    level by `QBlockCode`.
    """

    obj: Any
    infodock: InfoDock
    parent: Any
    options: QBlockCodeOptions
    span: Optional[Tuple[int,int]]
    subobjs: Sequence['QBlockCodeObj']
    _fmt_current: QTextCharFormat

    def __init__(self, obj:Any, infodock:InfoDock, parent:Any, options:QBlockCodeOptions=None):
        super().__init__()
        self.obj = obj
        self.infodock = infodock
        self.parent = parent
        self.options = options or QBlockCodeOptions()
        self.span = None
        self.subobjs = []
        self._fmt_current = None
        self.update_style()
        self.create_subobjs(obj)

    @staticmethod
    def fmt() -> QTextCharFormat:
        """
        Get text char formatting for this object
        """
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_node_mnemonic_color)
        return fmt

    def update_style(self):
        """
        Updates current rendering style before draw
        """
        self._fmt_current = self.fmt()
        if self.should_highlight():
            self._fmt_current.setBackground(Conf.disasm_view_operand_highlight_color)
            self._fmt_current.setFontWeight(QFont.Bold)

    def should_highlight(self) -> bool:
        """
        Determine whether this object should be drawn with highlight
        """
        selected = self.infodock.selected_qblock_code_obj
        return (selected is not None) and (selected is self or selected.obj is self.obj)

    def create_subobjs(self, obj):
        """
        Initialize any display subobjects for this object
        """

    def recreate_subobjs(self):
        self.subobjs.clear()
        self.create_subobjs(self.obj)

    def update(self):
        """
        Update self and parent objects
        """
        self.parent.update()

    def render_to_doc(self, cursor):
        """
        Add each subobject to the document
        """
        self.update_style()
        self.recreate_subobjs()
        span_min = cursor.position()
        for obj in self.subobjs:
            if type(obj) is str:
                cursor.insertText(obj, self._fmt_current)
            else:
                obj.render_to_doc(cursor)
        span_max = cursor.position()
        self.span = (span_min, span_max)

    def hit_test(self, pos:int) -> bool:
        """
        Determine whether a character offset falls within the span of this object
        """
        return self.span[0] <= pos < self.span[1]

    def get_hit_obj(self, pos:int) -> 'QBlockCodeObj':
        """
        Find the leaf node for a given character offset
        """
        if not self.hit_test(pos):
            return None
        for obj in self.subobjs:
            if type(obj) is not str:
                hit = obj.get_hit_obj(pos)
                if hit is not None:
                    return hit
        return self

    def _add_subobj(self, obj:'QBlockCodeObj'):
        """
        Add display object `obj` to the list of subobjects
        """
        self.subobjs.append(obj)

    def add_text(self, text:str):
        """
        Add a text leaf
        """
        self._add_subobj(text)

    def add_variable(self, var):
        self._add_subobj(QVariableObj(var, self.infodock, parent=self, options=self.options))

    def mousePressEvent(self, event:QMouseEvent): # pylint: disable=unused-argument
        self.infodock.select_qblock_code_obj(self)
        if event.button() == Qt.RightButton:
            self.infodock.disasm_view.show_context_menu_for_selected_object()

    def mouseDoubleClickEvent(self, event:QMouseEvent):
        pass

    @property
    def should_highlight_line(self):
        return any(obj.should_highlight_line
            for obj in self.subobjs
                if isinstance(obj, QBlockCodeObj))


class QVariableObj(QBlockCodeObj):
    """
    Renders a variable
    """

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_variable_label_color)
        return fmt

    def create_subobjs(self, obj):
        if self.options.show_variable_identifiers:
            ident = "<%s>" % (obj.ident if obj.ident else "")
        else:
            ident = ""
        self.add_text(obj.name + ident)


class QAilObj(QBlockCodeObj):
    """
    Renders an AIL object
    """

    def __init__(self, obj:Any, workspace, *args, stmt=None, **kwargs):
        self.stmt = stmt or obj
        self.workspace = workspace
        super().__init__(obj, *args, **kwargs)

    def create_subobjs(self, obj:Any):
        self.add_ailobj(obj)

    def add_ailobj(self, obj:Any):
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
        subobj = subobjcls(obj, self.workspace, self.infodock, parent=self, options=self.options, stmt=self.stmt)
        self._add_subobj(subobj)

    @property
    def should_highlight_line(self):
        ail_obj_ins_addr = getattr(self.obj, 'ins_addr', None)
        if ail_obj_ins_addr is not None and self.infodock.is_instruction_selected(ail_obj_ins_addr):
            return True
        return super().should_highlight_line

    def mousePressEvent(self, event:QMouseEvent): # pylint: disable=unused-argument
        super().mousePressEvent(event)
        button = event.button()
        if button == Qt.LeftButton:
            ail_obj_ins_addr = getattr(self.obj, 'ins_addr', None)
            if ail_obj_ins_addr is not None:
                self.infodock.select_instruction(ail_obj_ins_addr)

class QAilTextObj(QAilObj):
    """
    Renders an AIL object via __str__
    """

    def create_subobjs(self, obj:Any):
        self.add_text(str(obj))


class QAilAssignmentObj(QAilTextObj):
    """
    Renders an ailment.statement.Assignment
    """

    def create_subobjs(self, obj:ailment.statement.Assignment):
        self.add_ailobj(obj.dst)
        self.add_text(' = ')
        self.add_ailobj(obj.src)


class QAilStoreObj(QAilTextObj):
    """
    Renders an ailment.statement.Store
    """

    def create_subobjs(self, obj:ailment.statement.Store):
        if obj.variable is None or not self.options.show_variables:
            self.add_text('*(')
            self.add_ailobj(obj.addr)
            self.add_text(') = ')
            self.add_ailobj(obj.data)
        else:
            self.add_variable(obj.variable)
            self.add_text(' = ')
            self.add_ailobj(obj.data)


class QAilJumpObj(QAilTextObj):
    """
    Renders an ailment.statement.Jump
    """

    def create_subobjs(self, obj:ailment.statement.Jump):
        self.add_text("goto ")
        self.add_ailobj(obj.target)


class QAilConditionalJumpObj(QAilTextObj):
    """
    Renders an ailment.statement.ConditionalJump
    """

    def create_subobjs(self, obj:ailment.statement.ConditionalJump):
        self.add_text('if ')
        self.add_ailobj(obj.condition)

        if self.options.show_conditional_jump_targets:
            self.add_text(' goto ')
            self.add_ailobj(obj.true_target)
            self.add_text(' else goto ')
            self.add_ailobj(obj.false_target)


class QAilReturnObj(QAilTextObj):
    """
    Renders an ailment.statement.Return
    """

    def create_subobjs(self, obj:ailment.statement.Return):
        self.add_text('return ')
        for expr in obj.ret_exprs:
            self.add_ailobj(expr)


class QAilCallObj(QAilTextObj):
    """
    Renders an ailment.statement.Call
    """

    def create_subobjs(self, obj:ailment.statement.Call):
        if obj.ret_expr is not None and self.stmt is self.obj:
            self.add_ailobj(obj.ret_expr)
            self.add_text(' = ')
        self.add_ailobj(obj.target)
        self.add_text('(')
        if obj.args:
            for i, arg in enumerate(obj.args):
                if i > 0:
                    self.add_text(', ')
                self.add_ailobj(arg)
        self.add_text(')')


class QAilConstObj(QAilTextObj):
    """
    Renders an ailment.expression.Const
    """

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_operand_constant_color)
        return fmt

    def create_subobjs(self, obj:ailment.expression.Const):
        # take care of labels first
        kb = self.infodock.disasm_view.disasm.kb
        if obj.value in kb.labels:
            self.add_text(kb.labels[obj.value])
            return

        data_str = string_at_addr(
            self.workspace.instance.cfg,
            obj.value,
            self.workspace.instance.project,
         )
        if data_str:
            self.add_text(data_str)
        else:
            self.add_text("%#x" % (obj.value,))

    def should_highlight(self) -> bool:
        return (isinstance(self.infodock.selected_qblock_code_obj, QAilConstObj) and
                self.infodock.selected_qblock_code_obj.obj.value == self.obj.value)

    def mouseDoubleClickEvent(self, event:QMouseEvent):
        super().mouseDoubleClickEvent(event)
        button = event.button()
        if button == Qt.LeftButton:
            src_ins_addr = getattr(self.stmt, 'ins_addr', None)
            self.infodock.disasm_view.jump_to(self.obj.value,
                src_ins_addr=src_ins_addr,
                use_animation=True)


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

    def create_subobjs(self, obj: ailment.expression.Register):
        if obj.variable is not None and self.options.show_variables:
            self.add_variable(obj.variable)
        else:
            if hasattr(obj, 'reg_name'):
                s = "%s" % (obj.reg_name,)
            else:
                s = "reg_%d<%d>" % (obj.reg_offset, obj.bits // 8)
            self.add_text(s)

    def should_highlight(self) -> bool:
        sel = self.infodock.selected_qblock_code_obj
        return (isinstance(sel, QAilRegisterObj)
                and sel.obj == self.obj)


class QAilUnaryOpObj(QAilTextObj):
    """
    Renders an ailment.expression.UnaryOp
    """

    def create_subobjs(self, obj:ailment.expression.UnaryOp):
        self.add_text('(')
        self.add_text(obj.op + ' ')
        self.add_ailobj(obj.operand)
        self.add_text(')')


class QAilBinaryOpObj(QAilTextObj):
    """
    Renders an ailment.expression.BinaryOp
    """

    def create_subobjs(self, obj:ailment.expression.BinaryOp):
        self.add_text('(')
        self.add_ailobj(obj.operands[0])
        verbose_op = obj.OPSTR_MAP.get(obj.verbose_op, obj.verbose_op)
        if verbose_op is None:
            verbose_op = "unknown_op"
        self.add_text(' ' + verbose_op + ' ')
        self.add_ailobj(obj.operands[1])
        self.add_text(')')


class QAilConvertObj(QAilTextObj):
    """
    Renders an ailment.expression.Convert
    """

    def create_subobjs(self, obj:ailment.expression.Convert):
        self.add_text("Conv(%d->%d, " % (obj.from_bits, obj.to_bits))
        self.add_ailobj(obj.operand)
        self.add_text(")")


class QAilLoadObj(QAilTextObj):
    """
    Renders an ailment.expression.Load
    """

    def create_subobjs(self, obj:ailment.expression.Load):
        if obj.variable is not None and self.options.show_variables:
            self.add_variable(obj.variable)
        else:
            self.add_text('*(')
            self.add_ailobj(obj.addr)
            self.add_text(')')


class QIROpObj(QBlockCodeObj):
    """
    Renders a Lifter IR object
    """

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_ir_default_color)
        return fmt

    def __init__(self, obj:Any, *args, irobj=None, **kwargs):
        self.irobj = irobj or obj
        super().__init__(obj, *args, **kwargs)

    def create_subobjs(self, obj):
        self.add_irobj(obj.obj)

    def add_irobj(self, obj):
        subobjcls = {
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
        }.get(type(obj), QIROpTextObj)
        subobj = subobjcls(obj, self.infodock, parent=self, options=self.options, irobj=self.irobj)
        self._add_subobj(subobj)


class QIROpTextObj(QIROpObj):
    """
    Renders a Lifter IR object using the object's __str__, or as hexadecimal
    if an integer type.
    """

    def create_subobjs(self, obj:Any):
        if type(obj) is int:
            self.add_text('%#x' % obj)
        else:
            self.add_text(str(obj))


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
        return (isinstance(self.infodock.selected_qblock_code_obj, QIROpVexConstObj) and
                self.infodock.selected_qblock_code_obj.obj._con == self.obj._con)


class VexIRTmpWrapper:
    """
    A wrapper class for VEX temps
    """

    __slots__ = (
        'tid',
        'reg_name',
        )

    tid: TmpVar
    reg_name: Optional[str]

    def __init__(self, tid: TmpVar, reg_name: Optional[str] = None):
        self.tid = tid
        self.reg_name = reg_name or ('t%d' % self.tid)

    def __str__(self):
        return self.reg_name


class VexIRRegWrapper:
    """
    A wrapper class for VEX registers
    """

    __slots__ = (
        'offset',
        'reg_name',
        )

    offset: RegisterOffset
    reg_name: Optional[str]

    def __init__(self, offset: RegisterOffset, reg_name: Optional[str] = None):
        self.offset = offset
        self.reg_name = reg_name or ('offset=%s' % self.offset)

    def __str__(self):
        return self.reg_name


class QIROpVexWrTmpObj(QIROpTextObj):
    """
    Renders a pyvex.stmt.WrTmp
    """

    def create_subobjs(self, obj:pyvex.stmt.WrTmp):
        irsb = self.irobj.irsb
        self.add_irobj(VexIRTmpWrapper(obj.tmp))
        self.add_text(' = ')
        if isinstance(obj.data, pyvex.expr.Get):
            reg_name = irsb.arch.translate_register_name(
                obj.data.offset, obj.data.result_size(irsb.tyenv) // 8)
            self.add_irobj(VexIRRegWrapper(obj.data, reg_name))
        else:
            self.add_irobj(obj.data)


class QIROpVexRdTmpObj(QIROpTextObj):
    """
    Renders a pyvex.expr.RdTmp
    """

    def create_subobjs(self, obj:pyvex.expr.RdTmp):
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
        return (isinstance(self.infodock.selected_qblock_code_obj, QIROpVexTmpObj) and
                self.infodock.selected_qblock_code_obj.obj.tid == self.obj.tid)

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
        return (isinstance(self.infodock.selected_qblock_code_obj, QIROpVexRegObj) and
                self.infodock.selected_qblock_code_obj.obj.offset == self.obj.offset)


class QIROpVexStoreObj(QIROpTextObj):
    """
    Renders a pyvex.stmt.Store
    """

    def create_subobjs(self, obj:pyvex.stmt.Store):
        # "ST%s(%s) = %s" % (self.endness[-2:].lower(), self.addr, self.data)
        self.add_text('ST%s(' % (obj.endness[-2:].lower(),))
        self.add_irobj(obj.addr)
        self.add_text(') = ')
        self.add_irobj(obj.data)


class QIROpVexLoadObj(QIROpTextObj):
    """
    Renders a pyvex.expr.Load
    """

    def create_subobjs(self, obj:pyvex.expr.Load):
        self.add_text('LD%s:%s(' % (obj.end[-2:].lower(), obj.ty[4:]))
        self.add_irobj(obj.addr)
        self.add_text(')')


class QIROpVexPutObj(QIROpTextObj):
    """
    Renders a pyvex.stmt.Put
    """

    def create_subobjs(self, obj:pyvex.stmt.Put):
        irsb = self.irobj.irsb
        reg_name = irsb.arch.translate_register_name(obj.offset, obj.data.result_size(irsb.tyenv) // 8)
        self.add_text("PUT(")
        self.add_irobj(VexIRRegWrapper(obj.offset, reg_name))
        self.add_text(") = ")
        self.add_irobj(obj.data)


class QIROpVexExitObj(QIROpTextObj):
    """
    Renders a pyvex.stmt.Exit
    """

    def create_subobjs(self, obj:pyvex.stmt.Exit):
        irsb = self.irobj.irsb
        arch = irsb.arch
        reg_name = arch.translate_register_name(irsb.offsIP, arch.bits // 8)
        self.add_text("if (")
        self.add_irobj(obj.guard)
        self.add_text(") { PUT(")
        self.add_irobj(VexIRRegWrapper(obj.offsIP, reg_name))
        self.add_text(") = ")
        self.add_irobj(obj.dst.value)
        self.add_text("; ")
        self.add_irobj(obj.jumpkind)
        self.add_text(" }")


class QIROpVexBinopObj(QIROpTextObj):
    """
    Renders a pyvex.expr.Binop
    """

    def create_subobjs(self, obj:pyvex.expr.Binop):
        self.add_text(obj.op[4:])
        self.add_text('(')
        self.add_irobj(obj.args[0])
        self.add_text(',')
        self.add_irobj(obj.args[1])
        self.add_text(')')


class QIROpVexUnopObj(QIROpTextObj):
    """
    Renders a pyvex.expr.Unop
    """

    def create_subobjs(self, obj:pyvex.expr.Unop):
        self.add_text(obj.op[4:])
        self.add_text('(')
        self.add_irobj(obj.args[0])
        self.add_text(')')


class QBlockCode(QCachedGraphicsItem):
    """
    Top-level code widget for a selection of text. Will construct an AST using
    QBlockCodeObj, mirroring the structure associated with the target object.
    This text is then rendered using a QTextDocument, with appropriate styles
    applied to it. Interaction events will be propagated to corresponding
    objects.
    """

    GRAPH_ADDR_SPACING = 20

    addr: int
    _addr_str: str
    obj: QBlockCodeObj
    _config: ConfigurationManager
    disasm_view: 'QDisassemblyBaseControl'
    workspace: 'Workspace'
    infodock: InfoDock
    parent: Any

    def __init__(self, addr:int, obj:QBlockCodeObj, config:ConfigurationManager,
        disasm_view:'QDisassemblyBaseControl', workspace:'Workspace',
        infodock:InfoDock, parent:Any=None):
        super().__init__(parent=parent)
        self.addr = addr
        self._addr_str = "%08x" % self.addr
        self._addr_item: QGraphicsSimpleTextItem = None
        self.obj = obj
        self._width = 0
        self._height = 0
        self._config = config
        self.parent = parent
        self.workspace = workspace
        self.infodock = infodock
        self._disasm_view = disasm_view
        self._qtextdoc = QTextDocument()
        self._qtextdoc.setDefaultFont(self._config.disasm_font)
        self._qtextdoc.setDocumentMargin(0)

        self._addr_item = QGraphicsSimpleTextItem(self._addr_str, self)
        self._addr_item.setBrush(Conf.disasm_view_node_address_color)
        self._addr_item.setFont(Conf.disasm_font)

        self.update_document()
        self.setToolTip("Address: " + self._addr_str)

        self.refresh()

    def refresh(self):
        self._addr_item.setVisible(self._disasm_view.show_address)
        self._layout_items_and_update_size()

    def update_document(self):
        self._qtextdoc.clear()
        cur = QTextCursor(self._qtextdoc)
        self.obj.render_to_doc(cur)

    def paint(self, painter, option, widget):  #pylint: disable=unused-argument
        self.update_document()
        painter.setRenderHints(QPainter.Antialiasing
                               | QPainter.SmoothPixmapTransform
                               | QPainter.HighQualityAntialiasing)
        painter.setFont(self._config.disasm_font)


        if self.infodock.is_instruction_selected(self.addr) or self.obj.should_highlight_line:
            highlight_color = Conf.disasm_view_node_instruction_selected_background_color
            painter.setBrush(highlight_color)
            painter.setPen(highlight_color)
            painter.drawRect(0, 0, self.width, self.height)

        x = 0

        if self._disasm_view.show_address:
            x += self._addr_item.boundingRect().width() + self.GRAPH_ADDR_SPACING

        painter.translate(QPointF(x, 0))
        self._qtextdoc.drawContents(painter)

    #
    # Event handlers
    #

    def get_obj_for_mouse_event(self, event:QMouseEvent) -> QBlockCodeObj:
        p = event.pos()

        if self._disasm_view.show_address:
            offset = self._addr_item.boundingRect().width() + self.GRAPH_ADDR_SPACING
            p.setX(p.x() - offset)

        if p.x() >= 0:
            hitpos = self._qtextdoc.documentLayout().hitTest(p, Qt.HitTestAccuracy.ExactHit)
            if hitpos >= 0:
                return self.obj.get_hit_obj(hitpos)

        return None

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.infodock.select_instruction(self.addr)

        obj = self.get_obj_for_mouse_event(event)
        if obj is not None:
            obj.mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        obj = self.get_obj_for_mouse_event(event)
        if obj is not None:
            obj.mouseDoubleClickEvent(event)

    #
    # Private methods
    #

    def _layout_items_and_update_size(self):
        self.update_document()

        x, y = 0, 0
        if self._disasm_view.show_address:
            self._addr_item.setPos(x, y)
            x += self._addr_item.boundingRect().width() + self.GRAPH_ADDR_SPACING

        x += self._qtextdoc.size().width()
        y += self._qtextdoc.size().height()
        self._width = x
        self._height = y
        self.recalculate_size()

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
