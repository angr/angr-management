"""
The block tree: what a disassembly block shows of an AIL statement, a lifter IR op or a function header.

A :class:`BlockTreeNode` mirrors the structure of the object it shows. Leaves are strings; :meth:`BlockTreeNode.render`
walks the tree and returns the text as :class:`~angrmanagement.present.spans.Span` objects whose style is the node's
style key (see :meth:`BlockTreeNode.fmt`) and whose owner is the node, and records each node's character span so that
:meth:`BlockTreeNode.get_hit_obj` finds the node under a character offset. The Qt frontend puts the spans in a text
document; the terminal frontend writes them into cells.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angrmanagement.present.spans import Span, utf16_length

if TYPE_CHECKING:
    from angrmanagement.logic.disassembly import InfoDock

#: The style key added to a node's text while it is highlighted (selected, or equal to the selection).
HIGHLIGHT_STYLE = "disasm_view_operand_highlight_color"


def mouse_button_name(event: Any) -> str:
    """``"left"``, ``"right"`` or ``"other"`` for a Qt mouse event (imports Qt; only Qt events call it)."""
    from PySide6.QtCore import Qt  # pylint:disable=import-outside-toplevel

    button = event.button()
    if button == Qt.MouseButton.LeftButton:
        return "left"
    if button == Qt.MouseButton.RightButton:
        return "right"
    return "other"


class BlockTreeNodeOptions:
    """
    Various options to control display of QBlockCodeObj's
    """

    show_conditional_jump_targets: bool = True
    show_variables: bool = True
    show_variable_identifiers: bool = True


class BlockTreeNode:
    """
    Renders a generic "code" object and handles display related events.
    Instances of this class mirror an AST structure, with references in the
    `obj` property to whatever object should be displayed. Leaf nodes add
    text to the display document during render, which is handled at the top
    level by the frontend (`QBlockCode` in Qt).
    """

    obj: Any
    infodock: InfoDock
    parent: Any
    options: BlockTreeNodeOptions
    span: tuple[int, int] | None
    subobjs: list[BlockTreeNode | str]
    _fmt_current: Any
    display_address: bool
    top_margin_lines: int
    bottom_margin_lines: int

    def __init__(
        self,
        obj: Any,
        infodock: InfoDock,
        parent: Any,
        options: BlockTreeNodeOptions | None = None,
        display_address: bool = True,
        top_margin_lines: int = 0,
        bottom_margin_lines: int = 0,
    ) -> None:
        self.obj = obj
        self.infodock = infodock
        self.parent = parent
        self.options = options or BlockTreeNodeOptions()
        self.span = None
        self.subobjs = []
        self.display_address = display_address
        self._fmt_current = ""
        self.top_margin_lines = top_margin_lines
        self.bottom_margin_lines = bottom_margin_lines
        self.update_style()
        self.create_subobjs(obj)

    @staticmethod
    def fmt() -> str:
        """
        The style key of this node's text: a configuration entry name. (Subclasses written for the Qt frontend may
        still return a QTextCharFormat; the Qt frontend draws it as it is.)
        """
        return "disasm_view_node_mnemonic_color"

    @property
    def selection_key(self) -> Any:
        return None

    @property
    def style(self) -> str:
        """The style key the node's text has now: :meth:`fmt`, plus the highlight while it is highlighted."""
        return self._fmt_current

    def update_style(self) -> None:
        """
        Updates current rendering style before draw
        """
        fmt: Any = self.fmt()
        highlighted = self.should_highlight()
        if isinstance(fmt, str):
            self._fmt_current = fmt + " " + HIGHLIGHT_STYLE if highlighted else fmt
            return
        # a subclass written for the Qt frontend returns a QTextCharFormat; highlight it the way that frontend did
        from angrmanagement.ui.widgets import qblock_code  # pylint:disable=import-outside-toplevel

        self._fmt_current = qblock_code.highlight_char_format(fmt, highlighted)

    def should_highlight(self) -> bool:
        """
        Determine whether this object should be drawn with highlight
        """
        selected = self.infodock.selected_block_tree_node
        selection_key = self.selection_key
        r = (selected is not None) and (
            (selection_key is not None and selected == selection_key)
            or selected is self
            or (isinstance(selected, BlockTreeNode) and selected.obj is self.obj)
        )
        return r

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

    def render(self, start: int = 0) -> list[Span]:
        """
        The text of this node and its subobjects, in order, as spans; ``start`` is the character offset of the first.

        Each node's :attr:`span` becomes its ``(first, end)`` offsets, counted in UTF-16 code units as a Qt text
        document counts positions, so :meth:`hit_test` and :meth:`get_hit_obj` work on a frontend's document offsets.
        """
        self.update_style()
        self.recreate_subobjs()
        spans: list[Span] = []
        pos = start
        for obj in self.subobjs:
            if isinstance(obj, str):
                if obj:
                    spans.append(Span(obj, self._fmt_current, self))
                pos += utf16_length(obj)
            else:
                spans.extend(obj.render(pos))
                assert obj.span is not None
                pos = obj.span[1]
        self.span = (start, pos)
        return spans

    def render_to_doc(self, cursor) -> None:
        """
        Add each subobject to a Qt text document at ``cursor`` (imports Qt): :meth:`render`, one insert per span.
        """
        from angrmanagement.ui.widgets.qblock_code import qt_char_format  # pylint:disable=import-outside-toplevel

        for span in self.render(cursor.position()):
            cursor.insertText(span.text, qt_char_format(span.style))

    def hit_test(self, pos: int) -> bool:
        """
        Determine whether a character offset falls within the span of this object
        """
        if self.span is None:
            return False
        return self.span[0] <= pos < self.span[1]

    def get_hit_obj(self, pos: int) -> BlockTreeNode | None:
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

    def _add_subobj(self, obj: BlockTreeNode | str) -> None:
        """
        Add display object `obj` to the list of subobjects
        """
        self.subobjs.append(obj)

    def add_text(self, text: str) -> None:
        """
        Add a text leaf
        """
        self._add_subobj(text)

    def add_newline(self, cnt: int = 1) -> None:
        """
        Add a newline leaf
        """
        self._add_subobj("\n" * cnt)

    def add_variable(self, var) -> None:
        self._add_subobj(QVariableObj(var, self.infodock, parent=self, options=self.options))

    def activate(self, button: str) -> None:
        """
        The node was clicked: ``"left"`` toggles its selection, ``"right"`` selects it and asks the view for the
        selection's context menu.
        """
        selection_key = self.selection_key
        if selection_key is None:
            selection_key = self

        if button == "left":
            self.infodock.toggle_block_tree_node_selection(selection_key)
        elif button == "right":
            self.infodock.select_block_tree_node(selection_key)
            self.infodock.disasm_view.show_context_menu_for_selected_object()

    def activate_double(self, button: str) -> None:
        """The node was double-clicked with ``button``."""

    def mousePressEvent(self, event) -> None:
        """A Qt mouse press on the node: :meth:`activate` with its button."""
        self.activate(mouse_button_name(event))

    def mouseDoubleClickEvent(self, event) -> None:
        """A Qt double click on the node: :meth:`activate_double` with its button."""
        self.activate_double(mouse_button_name(event))

    @property
    def should_highlight_line(self):
        return any(obj.should_highlight_line for obj in self.subobjs if isinstance(obj, BlockTreeNode))


class QVariableObj(BlockTreeNode):
    """
    Renders a variable
    """

    @staticmethod
    def fmt() -> str:
        return "disasm_view_variable_label_color"

    def create_subobjs(self, obj) -> None:
        ident = "<%s>" % (obj.ident if obj.ident else "") if self.options.show_variable_identifiers else ""
        self.add_text(obj.name + ident)
