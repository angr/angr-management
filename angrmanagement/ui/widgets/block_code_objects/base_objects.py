from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QMouseEvent, QTextCharFormat

from angrmanagement.config import Conf

if TYPE_CHECKING:
    from collections.abc import Sequence

    from angrmanagement.logic.disassembly import InfoDock


class QBlockCodeOptions:
    """
    Various options to control display of QBlockCodeObj's
    """

    show_conditional_jump_targets: bool = True
    show_variables: bool = True
    show_variable_identifiers: bool = True


class QBlockCodeObj:
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
    span: tuple[int, int] | None
    subobjs: Sequence[QBlockCodeObj]
    _fmt_current: QTextCharFormat

    def __init__(self, obj: Any, infodock: InfoDock, parent: Any, options: QBlockCodeOptions = None) -> None:
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

    def update_style(self) -> None:
        """
        Updates current rendering style before draw
        """
        self._fmt_current = self.fmt()
        if self.should_highlight():
            self._fmt_current.setBackground(Conf.disasm_view_operand_highlight_color)
            self._fmt_current.setFontWeight(QFont.Weight.Bold)

    def should_highlight(self) -> bool:
        """
        Determine whether this object should be drawn with highlight
        """
        selected = self.infodock.selected_qblock_code_obj
        return (selected is not None) and (selected is self or selected.obj is self.obj)

    def create_subobjs(self, obj) -> None:
        """
        Initialize any display subobjects for this object
        """

    def recreate_subobjs(self) -> None:
        self.subobjs.clear()
        self.create_subobjs(self.obj)

    def update(self) -> None:
        """
        Update self and parent objects
        """
        self.parent.update()

    def render_to_doc(self, cursor) -> None:
        """
        Add each subobject to the document
        """
        self.update_style()
        self.recreate_subobjs()
        span_min = cursor.position()
        for obj in self.subobjs:
            if isinstance(obj, str):
                cursor.insertText(obj, self._fmt_current)
            else:
                obj.render_to_doc(cursor)
        span_max = cursor.position()
        self.span = (span_min, span_max)

    def hit_test(self, pos: int) -> bool:
        """
        Determine whether a character offset falls within the span of this object
        """
        return self.span[0] <= pos < self.span[1]

    def get_hit_obj(self, pos: int) -> QBlockCodeObj:
        """
        Find the leaf node for a given character offset
        """
        if not self.hit_test(pos):
            return None
        for obj in self.subobjs:
            if not isinstance(obj, str):
                hit = obj.get_hit_obj(pos)
                if hit is not None:
                    return hit
        return self

    def _add_subobj(self, obj: QBlockCodeObj) -> None:
        """
        Add display object `obj` to the list of subobjects
        """
        self.subobjs.append(obj)

    def add_text(self, text: str) -> None:
        """
        Add a text leaf
        """
        self._add_subobj(text)

    def add_variable(self, var) -> None:
        self._add_subobj(QVariableObj(var, self.infodock, parent=self, options=self.options))

    def mousePressEvent(self, event: QMouseEvent) -> None:  # pylint: disable=unused-argument
        self.infodock.select_qblock_code_obj(self)
        if event.button() == Qt.MouseButton.RightButton:
            self.infodock.disasm_view.show_context_menu_for_selected_object()

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        pass

    @property
    def should_highlight_line(self):
        return any(obj.should_highlight_line for obj in self.subobjs if isinstance(obj, QBlockCodeObj))


class QVariableObj(QBlockCodeObj):
    """
    Renders a variable
    """

    @staticmethod
    def fmt() -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(Conf.disasm_view_variable_label_color)
        return fmt

    def create_subobjs(self, obj) -> None:
        ident = "<%s>" % (obj.ident if obj.ident else "") if self.options.show_variable_identifiers else ""
        self.add_text(obj.name + ident)
