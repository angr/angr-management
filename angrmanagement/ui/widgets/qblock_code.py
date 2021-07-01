from PySide2.QtGui import QPainter, QTextDocument, QTextCursor, QTextCharFormat, QFont, QMouseEvent
from PySide2.QtCore import Qt, QPointF, QRectF, QObject
from PySide2.QtWidgets import QGraphicsSimpleTextItem
from typing import Any, Mapping, Sequence, Optional, Tuple

import ailment
import pyvex
from archinfo import RegisterOffset, TmpVar

from ...config import Conf, ConfigurationManager
from ...logic.disassembly.info_dock import InfoDock
from .qgraph_object import QCachedGraphicsItem


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
    options: Mapping[str, Any]
    span: Optional[Tuple[int,int]]
    subobjs: Sequence['QBlockCodeObj']
    _fmt_current: QTextCharFormat

    def __init__(self, obj:Any, infodock:InfoDock, parent:Any, options:Mapping[str, Any]=None):
        super().__init__()
        self.obj = obj
        self.infodock = infodock
        self.parent = parent
        self.options = options or {}
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
        return self.infodock.selected_qblock_code_obj is self

    def create_subobjs(self, obj):
        """
        Initialize any display subobjects for this object
        """
        raise NotImplementedError()

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
        self._add_subobj(QVariableObj(var, self.infodock, parent=self))

    def mousePressEvent(self, event:QMouseEvent):
        self.infodock.select_qblock_code_obj(self)

    def mouseDoubleClickEvent(self, event:QMouseEvent):
        pass


class QVariableObj(QBlockCodeObj):
    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_variable_label_color)
        return fmt

    def create_subobjs(self, obj):
        self.add_text(obj.name)


class QAilObj(QBlockCodeObj):
    def __init__(self, obj:Any, *args, stmt=None, **kwargs):
        self.stmt = stmt or obj
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
        subobj = subobjcls(obj, self.infodock, parent=self, options=self.options, stmt=self.stmt)
        self._add_subobj(subobj)


class QAilTextObj(QAilObj):
    def create_subobjs(self, obj:Any):
        self.add_text(str(obj))


class QAilAssignmentObj(QAilTextObj):
    def create_subobjs(self, obj:ailment.statement.Assignment):
        self.add_ailobj(obj.dst)
        self.add_text(' = ')
        self.add_ailobj(obj.src)


class QAilStoreObj(QAilTextObj):
    def create_subobjs(self, obj:ailment.statement.Store):
        if obj.variable is None:
            self.add_text('*(')
            self.add_ailobj(obj.addr)
            self.add_text(') = ')
            self.add_ailobj(obj.data)
        else:
            self.add_variable(obj.variable)
            self.add_text(' = ')
            self.add_ailobj(obj.data)


class QAilJumpObj(QAilTextObj):
    def create_subobjs(self, obj:ailment.statement.Jump):
        self.add_text("goto ")
        self.add_ailobj(obj.target)


class QAilConditionalJumpObj(QAilTextObj):
    def create_subobjs(self, obj:ailment.statement.ConditionalJump):
        self.add_text('if ')
        self.add_ailobj(obj.condition)

        if self.options.get('show_conditional_jump_targets', True):
            self.add_text(' goto ')
            self.add_ailobj(obj.true_target)
            self.add_text(' else goto ')
            self.add_ailobj(obj.false_target)


class QAilReturnObj(QAilTextObj):
    def create_subobjs(self, obj:ailment.statement.Return):
        self.add_text('return ')
        for expr in obj.ret_exprs:
            self.add_ailobj(expr)


class QAilCallObj(QAilTextObj):
    def create_subobjs(self, obj:ailment.statement.Call):
        self.add_text('call ')
        self.add_ailobj(obj.target)


class QAilConstObj(QAilTextObj):
    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_operand_constant_color)
        return fmt

    def create_subobjs(self, obj:ailment.expression.Const):
        kb = self.infodock.disasm_view.disasm.kb
        if obj.value in kb.labels:
            self.add_text(kb.labels[obj.value])
        else:
            self.add_text("%#x" % (obj.value,))

    def should_highlight(self) -> bool:
        return (isinstance(self.infodock.selected_qblock_code_obj, QAilConstObj) and
                self.infodock.selected_qblock_code_obj.obj.value == self.obj.value)

    def mousePressEvent(self, event:QMouseEvent):
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event:QMouseEvent):
        super().mouseDoubleClickEvent(event)
        button = event.button()
        if button == Qt.LeftButton:
            src_ins_addr = getattr(self.stmt, 'ins_addr', None)
            self.infodock.disasm_view.jump_to(self.obj.value,
                src_ins_addr=src_ins_addr,
                use_animation=True)


class QAilTmpObj(QAilTextObj):
    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_operand_color)
        return fmt


class QAilRegisterObj(QAilTextObj):
    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_operand_color)
        return fmt

    def create_subobjs(self, obj: ailment.expression.Register):
        if hasattr(obj, 'reg_name'):
            s = "%s" % (obj.reg_name,)
        elif obj.variable is None:
            s = "reg_%d<%d>" % (obj.reg_offset, obj.bits // 8)
        else:
            s = "%s" % str(obj.variable.name)
        self.add_text(s)

    def should_highlight(self) -> bool:
        return (isinstance(self.infodock.selected_qblock_code_obj, QAilRegisterObj) and
                self.infodock.selected_qblock_code_obj.obj.reg_name == self.obj.reg_name)


class QAilUnaryOpObj(QAilTextObj):
    def create_subobjs(self, obj:ailment.expression.UnaryOp):
        self.add_text('(')
        self.add_text(obj.op + ' ')
        self.add_ailobj(obj.operand)
        self.add_text(')')


class QAilBinaryOpObj(QAilTextObj):
    def create_subobjs(self, obj:ailment.expression.BinaryOp):
        self.add_text('(')
        self.add_ailobj(obj.operands[0])
        self.add_text(' ' + obj.OPSTR_MAP.get(obj.verbose_op, obj.verbose_op) + ' ')
        self.add_ailobj(obj.operands[1])
        self.add_text(')')


class QAilConvertObj(QAilTextObj):
    def create_subobjs(self, obj:ailment.expression.Convert):
        self.add_text("Conv(%d->%d, " % (obj.from_bits, obj.to_bits))
        self.add_ailobj(obj.operand)
        self.add_text(")")


class QAilLoadObj(QAilTextObj):
    def create_subobjs(self, obj:ailment.expression.Load):
        self.add_text('*(')
        self.add_ailobj(obj.addr)
        self.add_text(')')


class QIROpObj(QBlockCodeObj):
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
    def create_subobjs(self, obj:Any):
        if type(obj) is int:
            self.add_text('%#x' % obj)
        else:
            self.add_text(str(obj))


class QIROpVexConstObj(QIROpTextObj):
    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_operand_constant_color)
        return fmt

    def should_highlight(self) -> bool:
        return (isinstance(self.infodock.selected_qblock_code_obj, QIROpVexConstObj) and
                self.infodock.selected_qblock_code_obj.obj._con == self.obj._con)


class VexIRTmpWrapper:
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
    def create_subobjs(self, obj:pyvex.expr.RdTmp):
        self.add_irobj(VexIRTmpWrapper(obj.tmp))


class QIROpVexTmpObj(QIROpTextObj):
    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_operand_color)
        return fmt

    def should_highlight(self) -> bool:
        return (isinstance(self.infodock.selected_qblock_code_obj, QIROpVexTmpObj) and
                self.infodock.selected_qblock_code_obj.obj.tid == self.obj.tid)

class QIROpVexRegObj(QIROpTextObj):

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_operand_color)
        return fmt

    def should_highlight(self) -> bool:
        return (isinstance(self.infodock.selected_qblock_code_obj, QIROpVexRegObj) and
                self.infodock.selected_qblock_code_obj.obj.offset == self.obj.offset)


class QIROpVexStoreObj(QIROpTextObj):
    def create_subobjs(self, obj:pyvex.stmt.Store):
        # "ST%s(%s) = %s" % (self.endness[-2:].lower(), self.addr, self.data)
        self.add_text('ST%s(' % (obj.endness[-2:].lower(),))
        self.add_irobj(obj.addr)
        self.add_text(') = ')
        self.add_irobj(obj.data)


class QIROpVexLoadObj(QIROpTextObj):
    def create_subobjs(self, obj:pyvex.expr.Load):
        self.add_text('LD%s:%s(' % (obj.end[-2:].lower(), obj.ty[4:]))
        self.add_irobj(obj.addr)
        self.add_text(')')


class QIROpVexPutObj(QIROpTextObj):
    def create_subobjs(self, obj:pyvex.stmt.Put):
        irsb = self.irobj.irsb
        reg_name = irsb.arch.translate_register_name(obj.offset, obj.data.result_size(irsb.tyenv) // 8)
        self.add_text("PUT(")
        self.add_irobj(VexIRRegWrapper(obj.offset, reg_name))
        self.add_text(") = ")
        self.add_irobj(obj.data)


class QIROpVexExitObj(QIROpTextObj):
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
    def create_subobjs(self, obj:pyvex.expr.Binop):
        self.add_text(obj.op[4:])
        self.add_text('(')
        self.add_irobj(obj.args[0])
        self.add_text(',')
        self.add_irobj(obj.args[1])
        self.add_text(')')


class QIROpVexUnopObj(QIROpTextObj):
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

        self._layout_items_and_update_size()

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
        if self.infodock.is_instruction_selected(self.addr):
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
