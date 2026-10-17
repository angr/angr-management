from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Literal

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence, QShortcut, QTextCursor, QTextFormat
from PySide6.QtWidgets import (
    QComboBox,
    QDockWidget,
    QFrame,
    QHBoxLayout,
    QMainWindow,
    QTableWidget,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.config import Conf
from angrmanagement.present.code import (
    CodePresenter,
    register_code_commands,
)
from angrmanagement.present.code import floor_comment_addr as _floor_comment_addr
from angrmanagement.present.code import snap_comment_addr as _snap_comment_addr
from angrmanagement.ui.dialogs.jumpto import JumpTo
from angrmanagement.ui.documents import QCodeDocument
from angrmanagement.ui.toolbars import NavToolbar
from angrmanagement.ui.widgets.qccode_edit import QCCodeEdit
from angrmanagement.ui.widgets.qdecomp_options import QDecompilationOptions
from angrmanagement.ui.widgets.qfind_bar import QFindBar
from angrmanagement.ui.widgets.qpattern_library import QPatternLibrary

from .view import FunctionView

if TYPE_CHECKING:
    from collections.abc import Callable

    from angr.knowledge_plugins.functions.function import Function
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal
    from PySide6.QtWidgets import QPushButton

    from angrmanagement.data.instance import Instance
    from angrmanagement.data.object_container import ObjectContainer
    from angrmanagement.ui.workspace import Workspace

log = logging.getLogger(__name__)

__all__ = ["CodeView", "_floor_comment_addr", "_snap_comment_addr"]


def _forward(name: str, doc: str | None = None):
    """A property that reads and writes the presenter's attribute ``name``."""

    def fget(self):
        return getattr(self.presenter, name)

    def fset(self, value) -> None:
        setattr(self.presenter, name, value)

    return property(fget, fset, doc=doc or f"The presenter's ``{name}``.")


class CodeView(FunctionView):
    """
    A view to display pseudocode or source code. You should control this view by manipulating and observing its four
    ObjectContainers: .addr, .current_node, .codegen, and .function.

    The state and the actions are the :class:`~angrmanagement.present.code.CodePresenter`'s (``self.presenter``);
    this class adds the Qt text editor, docks, dialogs and keys, and forwards the rest.
    """

    presenter: CodePresenter

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        presenter = CodePresenter(workspace, instance, default_docking_position)
        super().__init__("pseudocode", workspace, default_docking_position, instance, presenter=presenter)

        self.base_caption = "Pseudocode"

        self.current_node: ObjectContainer = presenter.current_node
        self.addr: ObjectContainer | int = presenter.addr
        self.codegen: Any = presenter.codegen

        self._textedit: QCCodeEdit | None = None
        self._doc: QCodeDocument | None = None
        self._options: QDecompilationOptions | None = None
        self._nav_toolbar: NavToolbar | None = None
        self._view_selector: QComboBox | None = None
        self._summary_textedit: QTextEdit | None = None
        self._pattern_library: QPatternLibrary | None = None
        self._clear_highlights_btn: QPushButton | None = None
        self._patterns_dock: QDockWidget | None = None
        self._summary_dock: QDockWidget | None = None

        self._find_bar: QFindBar | None = None
        self._chunk_selections: list[QTextEdit.ExtraSelection] = []
        self._find_selections: list[QTextEdit.ExtraSelection] = []
        self._pattern_selections: list[QTextEdit.ExtraSelection] = []

        self._init_widgets()
        self._init_shortcuts()

        self._textedit.cursorPositionChanged.connect(self._on_cursor_position_changed)
        self._textedit.selectionChanged.connect(self._on_cursor_position_changed)
        self._textedit.mouse_double_clicked.connect(self._on_mouse_doubleclicked)
        self._function.am_subscribe(self._on_new_function)
        self.codegen.am_subscribe(self._on_codegen_changes)
        self.codegen.am_subscribe(self._on_codegen_for_patterns)
        self.addr.am_subscribe(self._on_new_addr)
        self.current_node.am_subscribe(self._on_new_node)
        self.instance.annotations.bookmarks.am_subscribe(self._on_bookmarks_changed)

    def closeEvent(self, event) -> None:
        self.instance.annotations.bookmarks.am_unsubscribe(self._on_bookmarks_changed)
        super().closeEvent(event)

    def _on_bookmarks_changed(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self.refresh_bookmarks()

    @classmethod
    def register_commands(cls, workspace: Workspace) -> None:
        """
        Register commands that can be run for this view. They run on the focused view's presenter.
        """
        register_code_commands(workspace)

    def _focus_core(self, focus: bool, focus_addr: int | None) -> None:
        self.presenter.focus_core(focus, focus_addr)

    #
    # The presenter's state
    #

    jump_history = _forward("jump_history")
    vars_must_struct: set[str] = _forward("vars_must_struct")  # type: ignore[assignment]
    _last_function = _forward("last_function")
    _find_matches = _forward("find_matches")
    _find_index = _forward("find_index")
    _highlight_layers = _forward("highlight_layers")
    _highlighted_patterns = _forward("highlighted_patterns")
    _mirrored_codegen = _forward("mirrored_codegen")
    _mirrored_comments = _forward("mirrored_comments")

    #
    # Properties
    #

    @property
    def textedit(self):
        return self._textedit

    @property
    def document(self):
        return self._doc

    @property
    def flavor(self) -> str | None:
        """
        Return the current flavor of the codegen. This is just a convenient wrapper around self.codegen.flavor.
        """
        return self.presenter.flavor

    @property
    def best_flavor(self) -> str:
        return self.presenter.best_flavor

    #
    # What the presenter asks of its view
    #

    def cursor_position(self) -> int:
        return self._textedit.textCursor().position() if self._textedit is not None else 0

    def selection_range(self) -> tuple[int, int]:
        cursor = self._textedit.textCursor()
        return cursor.selectionStart(), cursor.selectionEnd()

    def selected_text(self) -> str:
        return self._textedit.textCursor().selectedText()

    def plain_text(self) -> str:
        return self._textedit.toPlainText()

    def set_cursor_position(self, pos: int) -> None:
        cursor = self._textedit.textCursor()
        cursor.setPosition(pos)
        self._textedit.setTextCursor(cursor)

    def select_range(self, start: int, end: int) -> None:
        cursor = self._textedit.textCursor()
        cursor.setPosition(start)
        cursor.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
        self._textedit.setTextCursor(cursor)

    def focus_text(self) -> None:
        self._textedit.setFocus()

    def on_flavors_changed(self) -> None:
        self._update_available_views(self.presenter.available_flavors)

    def on_chunks_changed(self) -> None:
        self.highlight_chunks(self.presenter.chunks)

    def on_pattern_highlight_changed(self) -> None:
        self._rebuild_pattern_selections()

    def on_pattern_highlight_cleared(self) -> None:
        self._pattern_selections = []
        self._apply_extra_selections()
        self._update_clear_highlights()

    def on_find_matches_changed(self) -> None:
        color = Conf.disasm_view_operand_highlight_color
        self._find_selections = [self._make_selection(start, end, color) for start, end in self._find_matches]
        self._apply_extra_selections()

    def find_bar_closed(self) -> None:
        self._textedit.setFocus()

    def close_view_requested(self) -> None:
        self.close()

    def copy(self) -> None:
        self._textedit.copy()

    def select_all(self) -> None:
        self._textedit.selectAll()

    def zoom_in(self) -> None:
        self._textedit.zoomIn()

    def zoom_out(self) -> None:
        self._textedit.zoomOut()

    #
    # Public methods
    #

    def reload(self) -> None:
        self.presenter.reload()

    def set_codeedit_palette(self, palette):
        if self._textedit is not None:
            self._textedit.setPalette(palette)

    def decompile(
        self,
        clear_prototype: bool = False,
        focus: bool = False,
        focus_addr=None,
        flavor: str | None = None,
        reset_cache: bool = False,
        regen_clinic: bool = True,
        on_finish: Callable[[], None] | None = None,
    ) -> None:
        self.presenter.decompile(
            clear_prototype=clear_prototype,
            focus=focus,
            focus_addr=focus_addr,
            flavor=flavor,
            reset_cache=reset_cache,
            regen_clinic=regen_clinic,
            on_finish=on_finish,
        )

    def highlight_chunks(self, chunks) -> None:
        color = Conf.pseudocode_highlight_color
        self._chunk_selections = [self._make_selection(start, end, color) for start, end in chunks]
        self._apply_extra_selections()

    def highlight_pattern(self, func_addr: int, copies: list[frozenset[int]], layer: str = "discover") -> None:
        """Band every line of ``func_addr``'s pseudocode that renders one of the copies' instructions.

        Each ``layer`` is independent. The highlight waits for the function if it is still
        being decompiled, follows the pseudocode when it is regenerated, and goes away when
        another function is shown.
        """
        self.presenter.highlight_pattern(func_addr, copies, layer)

    def set_pattern_highlight(self, name: str, on: bool) -> None:
        """Band the named pattern's matches in whatever function is shown: the calls the
        outlined ones became, found in the pseudocode itself, and the lines of the rest."""
        self.presenter.set_pattern_highlight(name, on)

    def is_pattern_highlighted(self, name: str) -> bool:
        return self.presenter.is_pattern_highlighted(name)

    @property
    def has_pattern_highlight(self) -> bool:
        """Whether anything is highlighted: a Discover family, a pattern's matches, or either in the disassembly."""
        return self.presenter.has_pattern_highlight

    def _disasm_pattern_addrs(self) -> set[int]:
        return self.presenter.disasm_pattern_addrs()

    def clear_pattern_highlight(self) -> bool:
        """Drop every pattern highlight; returns whether there was any."""
        return self.presenter.clear_pattern_highlight()

    def _update_clear_highlights(self) -> None:
        if self._clear_highlights_btn is not None:
            self._clear_highlights_btn.setEnabled(self.has_pattern_highlight)

    @property
    def pattern_highlighted_lines(self) -> list[int]:
        """Block numbers of the lines the pattern highlight covers."""
        return [sel.cursor.blockNumber() for sel in self._pattern_selections]

    def _highlight_addrs(self) -> set[int]:
        """Every instruction address a highlight layer or a highlighted pattern asks for here."""
        return self.presenter.highlight_addrs()

    def _highlighted_call_names(self) -> set[str]:
        return self.presenter.highlighted_call_names()

    def _call_positions(self, call_names: set[str]) -> list[int]:
        """Where the pseudocode calls any of ``call_names``."""
        return self.presenter.call_positions(call_names)

    def pattern_call_count(self, name: str) -> int:
        """How many times the pseudocode on screen calls the named pattern's call name."""
        return self.presenter.pattern_call_count(name)

    def _rebuild_pattern_selections(self) -> None:
        self._pattern_selections = []
        positions = self.presenter.pattern_highlight_positions()
        if positions and self._doc is not None:
            lines: dict[int, int] = {}
            for pos in positions:
                block = self._doc.findBlock(pos)
                lines.setdefault(block.blockNumber(), block.position())
            for pos in sorted(lines.values()):
                sel = QTextEdit.ExtraSelection()
                sel.cursor = self._textedit.textCursor()
                sel.cursor.setPosition(pos)
                sel.cursor.clearSelection()
                sel.format.setBackground(Conf.pseudocode_pattern_highlight_color)
                sel.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
                self._pattern_selections.append(sel)
        self._apply_extra_selections()
        self._update_clear_highlights()

    def refresh_bookmarks(self) -> None:
        self._apply_extra_selections()

    def _bookmark_selections(self) -> list[QTextEdit.ExtraSelection]:
        """
        A full-width line highlight for every bookmarked address rendered in this function.
        """
        if self._doc is None:
            return []
        selections = []
        for pos in self.presenter.bookmark_positions():
            sel = QTextEdit.ExtraSelection()
            sel.cursor = self._textedit.textCursor()
            sel.cursor.setPosition(pos)
            sel.cursor.clearSelection()
            sel.format.setBackground(Conf.pseudocode_bookmark_color)
            sel.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
            selections.append(sel)
        return selections

    def sync_kb_comments(self) -> bool:
        """
        Mirror ``kb.comments`` for this function into the codegen's statement comments (see
        :meth:`CodePresenter.sync_kb_comments`). Returns whether a re-render is needed.
        """
        return self.presenter.sync_kb_comments()

    #
    # Find in view
    #

    def show_find_bar(self) -> None:
        """
        Open the incremental find bar, seeded with the current selection if there is one.
        """
        self.presenter.show_find_bar()

    def find_next(self) -> None:
        self.presenter.find_next()

    def find_previous(self) -> None:
        self.presenter.find_previous()

    def _update_find_matches(self) -> None:
        self.presenter.update_find_matches()

    def _step_find_match(self, delta: int) -> None:
        if delta > 0:
            self.presenter.find_next()
        else:
            self.presenter.find_previous()

    def _select_find_match(self, index: int) -> None:
        self.presenter.select_find_match(index)

    def _on_find_bar_closed(self) -> None:
        self.presenter.on_find_bar_closed()

    def _make_selection(self, start: int, end: int, color) -> QTextEdit.ExtraSelection:
        sel = QTextEdit.ExtraSelection()
        sel.cursor = self._textedit.textCursor()
        sel.cursor.setPosition(start)
        sel.cursor.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
        sel.format.setBackground(color)
        return sel

    def _apply_extra_selections(self) -> None:
        self._textedit.setExtraSelections(
            self._pattern_selections + self._bookmark_selections() + self._chunk_selections + self._find_selections
        )

    def variable_manager(self, func_addr: int | Literal["global"] | None = None) -> VariableManagerInternal | None:
        return self.presenter.variable_manager(func_addr)

    #
    # Event callbacks
    #

    def _on_new_addr(self, already_moved: bool = False, focus: bool = False, **kwargs) -> None:
        self.presenter.on_new_addr(already_moved=already_moved, focus=focus, **kwargs)

    def _function_at(self, addr: int) -> Function | None:
        """
        The function owning the block that contains addr, or None if unknown.
        """
        return self.presenter.function_at(addr)

    def _on_new_node(self, **kwargs) -> None:  # pylint: disable=unused-argument
        self.addr.am_obj = self._textedit.get_src_to_inst()
        self.addr.am_event(already_moved=True)

    # pylint: disable=unused-argument
    def reload_patterns(self) -> None:
        if self._pattern_library is not None:
            self._pattern_library.reload()

    def _on_patterns_applied(self) -> None:
        """Patterns turned on or off from this view's dock: show their effect on this function now."""
        if not self._function.am_none:
            self.decompile(reset_cache=True)

    def _on_codegen_for_patterns(self, **_) -> None:
        # the outliner pass's numbers change with every decompilation, and the text the
        # pattern highlight points into has been regenerated
        self.reload_patterns()
        self._rebuild_pattern_selections()

    @property
    def patterns_dock(self) -> QDockWidget | None:
        return self._patterns_dock

    @property
    def patterns_table(self) -> QTableWidget | None:
        return None if self._pattern_library is None else self._pattern_library.table

    def _on_codegen_changes(self, already_regenerated: bool = False, event: str | None = None, **kwargs) -> None:
        """
        The callback function that triggers an update of the codegen.

        :param already_regenerated: True if we only want to re-render the text and do not intend to change the text.
                                    Setting it to True will ignore `event` and other parameters.
        :param event:               The event to perform. For example, "retype_variable" will cause a re-flow of
                                    variable types. Leaving it unspecified will lead to regeneration of text (which is
                                    the default behavior).
                                    Supported events: retype_variable
        :param kwargs:              Keyword arguments that are required in each event.
        :return:
        """
        if self.codegen.am_none:
            self._doc = None
            self.presenter.rendered = False
            self._textedit.clear()
            return

        if self.sync_kb_comments():
            # newly mirrored comments are only visible after a re-render
            already_regenerated = False

        old_blockno: int | None = None
        old_node: Any | None = None
        old_font = None
        scroll_pos = None
        if self._last_function is self._function.am_obj and self._doc is not None:
            # we are re-rendering the current function (e.g., triggered by a node renaming). the cursor should stay at
            # the same node, and the scroll position should stay the same
            old_cursor: QTextCursor = self._textedit.textCursor()
            old_pos = old_cursor.position()
            old_blockno = old_cursor.blockNumber()
            old_font = self._textedit.font()
            # TODO: If multiple instances of the node is referenced at the same line, we will always select the first
            #  node. We need to fix this by counting which node is selected.
            old_node = self._doc.get_node_at_position(old_pos)
            scroll_pos = self._textedit.verticalScrollBar().value()

        self._view_selector.setCurrentText(self.codegen.flavor)

        self.presenter.regenerate_codegen(already_regenerated, event, **kwargs)

        # the cursor moves as the document is set, and the presenter answers for a document only once it is shown
        self.presenter.rendered = True
        if self._doc is None:
            self._doc = QCodeDocument(self.codegen)
            self._textedit.setDocument(self._doc)
        else:
            # only update the text. do not set a new document. this avoids scrolling the textedit up and down
            self._doc._codegen = self.codegen
            self._doc.setPlainText(self.codegen.text)

        if old_blockno is not None:
            the_block = self._doc.findBlockByNumber(old_blockno)
            new_cursor: QTextCursor = QTextCursor(the_block)
            self._textedit.setFont(old_font)
            if old_node is not None:
                # find the first node starting from the current position
                for pos in self.codegen.map_pos_to_node._posmap.irange(
                    minimum=new_cursor.position(), maximum=new_cursor.position() + the_block.length()
                ):
                    elem = self.codegen.map_pos_to_node._posmap[pos]
                    if elem.obj is old_node:
                        new_cursor.setPosition(pos)
            self._textedit.setTextCursor(new_cursor)
        if scroll_pos is not None:
            # restore the scroll position
            self._textedit.verticalScrollBar().setValue(scroll_pos)

        if self.presenter.shows_options:
            self._options.show()
        else:
            self._options.hide()

        self.refresh_bookmarks()
        self._update_function_summary()

    def _on_new_function(self, focus: bool = False, focus_addr=None, flavor=None, **kwargs) -> None:  # pylint: disable=unused-argument
        # sets a new function. extra args are used in case this operation requires waiting for the decompiler
        self.presenter.on_new_function(focus=focus, focus_addr=focus_addr, flavor=flavor, **kwargs)

    def _on_cursor_position_changed(self) -> None:
        if self._doc is None:
            return
        self.presenter.cursor_moved(self._textedit.textCursor().position())

    def _navigate_to_function(self, from_addr: int, to_func: Function) -> None:
        self.presenter.navigate_to_function(from_addr, to_func)

    def _on_mouse_doubleclicked(self) -> None:
        if self._doc is None:
            return
        self.presenter.activate()

    def jump_to(self, addr: int, src_ins_addr=None) -> bool:  # pylint:disable=unused-argument
        return self.presenter.jump_to(addr, src_ins_addr)

    def jump_back(self) -> None:
        self.presenter.jump_back()

    def popup_jumpto_dialog(self) -> None:
        JumpTo(self, parent=self).show()

    def jump_forward(self) -> None:
        self.presenter.jump_forward()

    def jump_to_history_position(self, pos: int) -> None:
        self.presenter.jump_to_history_position(pos)

    def keyPressEvent(self, event):
        key = event.key()
        if key == Qt.Key_Tab:
            # Switch back to disassembly view
            self.workspace.jump_to(self._disassembly_target_addr())
            return True
        elif key == Qt.Key_G:
            # jump to window
            self.popup_jumpto_dialog()
            return True
        elif key == Qt.Key_Escape:
            # the first Escape dismisses a pattern highlight; with none shown it navigates back
            if not self.clear_pattern_highlight():
                self.jump_back()
            return True
        elif key == Qt.Key_Space and not self.codegen.am_none:
            self.presenter.next_flavor()
            return True

        return super().keyPressEvent(event)

    def _disassembly_target_addr(self) -> int | None:
        """
        The address the disassembly view should show for the current cursor; falls back to the function head when the
        cursor address is unset or points outside the binary (e.g., a synthesized node tagged with address 0).
        """
        return self.presenter.disassembly_target_addr()

    def _update_available_views(self, available) -> None:
        for _ in range(self._view_selector.count()):
            self._view_selector.removeItem(0)
        self._view_selector.addItems(available)

    def _on_view_selector_changed(self, index) -> None:
        self.presenter.select_flavor(self._view_selector.itemText(index))

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        window = QMainWindow()
        window.setWindowFlags(Qt.WindowType.Widget)

        # pseudo code text box
        self._textedit = QCCodeEdit(self)
        self._textedit.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByKeyboard | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self._textedit.setLineWrapMode(QCCodeEdit.NoWrap)
        self._textedit.background = Conf.palette_base
        window.setCentralWidget(self._textedit)

        # decompilation options; the presenter's decompilations use what they say
        self._options = QDecompilationOptions(self, self.instance)
        self.presenter.options = self._options
        options_dock = QDockWidget("Decompilation Options", self._options)
        window.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, options_dock)
        options_dock.setWidget(self._options)
        options_dock.setVisible(False)

        # the project's patterns, with what the outliner pass did with each here
        self._pattern_library = QPatternLibrary(
            self.workspace,
            self.instance,
            on_edit=self.workspace.edit_pattern,
            current_func=lambda: None if self._function.am_none else self._function.am_obj.addr,
            on_apply=self._on_patterns_applied,
            highlight=(self.is_pattern_highlighted, self.set_pattern_highlight),
            code_view=lambda: self,
        )
        self._patterns_dock = QDockWidget("Patterns", window)
        self._patterns_dock.setWidget(self._pattern_library)
        self._clear_highlights_btn = self._pattern_library.add_button(
            "Clear highlights", self.clear_pattern_highlight, "Remove every pattern highlight from the pseudocode (Esc)"
        )
        self._clear_highlights_btn.setEnabled(False)
        # the numbers may have changed while the dock was hidden
        self._patterns_dock.visibilityChanged.connect(lambda visible: visible and self.reload_patterns())
        window.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self._patterns_dock)
        self._patterns_dock.setVisible(False)

        # function summary dock
        self._summary_textedit = QTextEdit()
        self._summary_textedit.setReadOnly(True)
        self._summary_textedit.setPlaceholderText("No summary available. Use AI > Summarize Function to generate one.")
        self._summary_dock = QDockWidget("Function Summary", window)
        self._summary_dock.setWidget(self._summary_textedit)
        window.addDockWidget(Qt.DockWidgetArea.TopDockWidgetArea, self._summary_dock)
        self._summary_dock.setVisible(False)

        # status bar
        status_bar = QFrame()
        self._nav_toolbar = NavToolbar(
            self.jump_history, self.jump_back, self.jump_forward, self.jump_to_history_position, True, self
        )
        self._view_selector = QComboBox()
        self._view_selector.activated.connect(self._on_view_selector_changed)
        self._view_selector.setVisible(True)
        status_layout = QHBoxLayout()
        status_layout.addWidget(self._nav_toolbar.qtoolbar())
        status_layout.addStretch(0)
        summary_toggle_btn = QToolButton()
        summary_toggle_btn.setDefaultAction(self._summary_dock.toggleViewAction())
        status_layout.addWidget(summary_toggle_btn)
        options_toggle_btn = QToolButton()
        options_toggle_btn.setDefaultAction(options_dock.toggleViewAction())
        status_layout.addWidget(options_toggle_btn)
        patterns_toggle_btn = QToolButton()
        patterns_toggle_btn.setDefaultAction(self._patterns_dock.toggleViewAction())
        status_layout.addWidget(patterns_toggle_btn)
        status_layout.addWidget(self._view_selector)
        status_layout.setContentsMargins(3, 3, 3, 3)
        status_layout.setSpacing(3)
        status_bar.setLayout(status_layout)

        inner_layout = QHBoxLayout()
        inner_layout.addWidget(window)
        inner_layout.setContentsMargins(0, 0, 0, 0)
        inner_layout.setSpacing(0)
        inner_widget = QWidget()
        inner_widget.setLayout(inner_layout)

        # find bar
        self._find_bar = QFindBar(self)
        self._find_bar.query_changed.connect(self._update_find_matches)
        self._find_bar.find_next.connect(self.find_next)
        self._find_bar.find_previous.connect(self.find_previous)
        self._find_bar.closed.connect(self._on_find_bar_closed)
        self.presenter.find_bar = self._find_bar

        outer_layout = QVBoxLayout()
        outer_layout.addWidget(status_bar)
        outer_layout.addWidget(self._find_bar)
        outer_layout.addWidget(inner_widget)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        self.setLayout(outer_layout)

        self._textedit.focusWidget()

        self.workspace.plugins.instrument_code_view(self)

    def _init_shortcuts(self) -> None:
        for sequence, handler in [
            (QKeySequence.StandardKey.Find, self.show_find_bar),
            (QKeySequence(Qt.Key.Key_F3), self.find_next),
            (QKeySequence("Shift+F3"), self.find_previous),
        ]:
            shortcut = QShortcut(sequence, self, handler)
            shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)

    def _update_function_summary(self) -> None:
        """Update the function summary text box from the decompilation cache."""
        if self._summary_textedit is None:
            return
        summary = self.presenter.function_summary()
        if summary:
            self._summary_textedit.setPlainText(summary)
        else:
            self._summary_textedit.clear()

    def _maybe_auto_llm_refine(self) -> None:
        """Dispatch LLM refinement jobs for any auto-* options that are enabled."""
        self.presenter.maybe_auto_llm_refine()

    def _maybe_preload_callees(self) -> None:
        self.presenter.maybe_preload_callees()
