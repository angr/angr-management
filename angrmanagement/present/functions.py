"""The functions view without a toolkit: the table of functions, its filter and its context menu."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, ClassVar

from angr.analyses.code_tagging import CodeTags
from angr.rust.utils.demangler import demangle as rust_demangle
from angr.utils.library import get_cpp_function_name

from angrmanagement.config.color import Color
from angrmanagement.data.annotations import CommentKind

from .base import InstancePresenter, ask_text, container
from .keymap import table_keymap
from .menus import Menu, MenuEntry
from .tables import Column, ListTableModel
from .theme import StyleSpec

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from angr.knowledge_plugins.functions import Function, FunctionManager

    from angrmanagement.data.instance import Instance

    from .keymap import Keymap


class FunctionTableEntry:
    """
    A single entry in the function table as a proxy for the actual Function object.
    """

    __slots__ = ("_funcman", "addr", "_is_alignment")

    def __init__(self, funcman: FunctionManager, addr: int) -> None:
        self._funcman = funcman
        self.addr = addr
        #
        # cache
        #
        # caching is_alignment because it's used in filtering; otherwise every time we filter we would need to load
        # the spilled function back up from RuntimeDb.
        self._is_alignment = None

    def _meta_func(self) -> Function | None:
        try:
            return self._funcman.get_by_addr(self.addr, meta_only=True)
        except KeyError:
            return None

    @property
    def is_syscall(self) -> bool:
        func = self._meta_func()
        return bool(func.is_syscall) if func is not None else False

    @property
    def is_plt(self) -> bool:
        return self._funcman.is_plt_cached(self.addr)

    @property
    def is_simprocedure(self) -> bool:
        func = self._meta_func()
        return bool(func.is_simprocedure) if func is not None else False

    @property
    def is_alignment(self) -> bool:
        if self._is_alignment is None:
            func = self._meta_func()
            self._is_alignment = bool(func.is_alignment) if func is not None else False
        return self._is_alignment

    @property
    def from_signature(self) -> str | None:
        return self._funcman.get_from_signature(self.addr)

    @property
    def name(self) -> str | None:
        return self._funcman.get_func_name(self.addr)

    @property
    def demangled_name(self) -> str | None:
        func = self._meta_func()
        return func.demangled_name if func is not None else self.name

    @property
    def tags(self) -> list[str]:
        func = self._meta_func()
        return list(func.tags) if func is not None else []

    @property
    def size(self) -> int:
        func = self._meta_func()
        return func.size if func is not None else 0

    @property
    def number_of_blocks(self) -> int | None:
        return self._funcman.get_func_block_count(self.addr)

    @property
    def cyclomatic_complexity(self) -> int:
        func = self._meta_func()
        return func.cyclomatic_complexity if func is not None else 0

    @property
    def binary_name(self) -> str:
        func = self._meta_func()
        return (func.binary_name or "") if func is not None else ""


TAG_STRS = {
    CodeTags.HAS_XOR: "Xor",
    CodeTags.HAS_BITSHIFTS: "Shift",
    CodeTags.HAS_SQL: "SQL",
}


def tags_display_string(tags: Iterable[str]) -> str:
    return ", ".join(TAG_STRS.get(t, t) for t in tags)


def function_style_key(func: FunctionTableEntry) -> str:
    """The style key of a function's row: its colour says whether it is a syscall, a PLT stub, and so on."""
    if func.is_syscall:
        return "function_table_syscall_color"
    if func.is_plt:
        return "function_table_plt_color"
    if func.is_simprocedure:
        return "function_table_simprocedure_color"
    if func.is_alignment:
        return "function_table_alignment_color"
    return "function_table_color"


def neutral_color(color: Any) -> Color | None:
    """A plugin's colour, which may be a Color or a QColor, as a Color."""
    if color is None or isinstance(color, Color):
        return color
    if hasattr(color, "red") and hasattr(color, "alpha"):
        return Color(color.red(), color.green(), color.blue(), color.alpha())
    return None


class FunctionTableModel(ListTableModel[FunctionTableEntry]):
    """
    The functions of a FunctionManager. Plugins add columns after the built-in ones; alignment stubs are hidden
    unless :attr:`show_alignment` is set.
    """

    INLINE_COL = 0
    NAME_COL = 1
    TAGS_COL = 2
    ADDRESS_COL = 3
    BINARY_COL = 4
    SIZE_COL = 5
    BLOCKS_COL = 6
    COMPLEXITY_COL = 7

    COLUMNS: ClassVar[list[Column]] = [
        Column("Inline?", 3, checkable=True),
        Column("Name", 22),
        Column("Tags", 6),
        Column("Address", 8),
        Column("Binary", 10),
        Column("Size", 6),
        Column("Blocks", 6),
        Column("Complexity", stretch=True),
    ]
    Headers: ClassVar[list[str]] = [c.name for c in COLUMNS]

    def __init__(self, workspace, instance: Instance, on_select: Callable[[Function], None] | None = None) -> None:
        super().__init__()
        self.workspace = workspace
        self.instance = instance
        self.on_select = on_select
        self.function_manager: FunctionManager | None = None
        self.show_alignment: bool = False

    #
    # Columns, including the plugins'
    #

    def _plugin_column_count(self) -> int:
        return self.workspace.plugins.count_func_columns()

    @property
    def columns(self) -> list[Column]:
        columns = list(self.COLUMNS)
        for idx in range(self._plugin_column_count()):
            try:
                name = self.workspace.plugins.get_func_column(idx)
            except IndexError:
                break
            columns.append(Column(str(name)))
        return columns

    #
    # Rows
    #

    def load(self, function_manager: FunctionManager | None) -> None:
        """Show every function of ``function_manager``, or nothing when it is None."""
        self.function_manager = function_manager
        if function_manager is None:
            self.set_rows([])
            return
        self.set_rows(FunctionTableEntry(function_manager, addr) for addr in function_manager)

    def update(self, added: Iterable[int] = (), removed: Iterable[int] = ()) -> None:
        """Add the functions at ``added`` and drop those at ``removed``."""
        if self.function_manager is None:
            return
        removed = set(removed)
        if removed:
            self.set_rows([f for f in self.all_rows if f.addr not in removed])
        new = [FunctionTableEntry(self.function_manager, addr) for addr in added]
        if new:
            self.append_rows(new)

    def set_show_alignment(self, show: bool) -> None:
        self.show_alignment = show
        # showing more rows: the incremental filter would not bring them back
        self._filter_from_scratch = True
        self.refilter()

    def function_at(self, row: int) -> Function | None:
        entry = self.row(row)
        if entry is None or self.function_manager is None:
            return None
        try:
            return self.function_manager.get_by_addr(entry.addr)
        except KeyError:
            return None

    def functions(self, rows: Iterable[int]) -> list[Function]:
        funcs = []
        kb = self.instance.kb
        if kb is None:
            return funcs
        for entry in self.objects(rows):
            with contextlib.suppress(KeyError):
                funcs.append(kb.functions[entry.addr])
        return funcs

    def count_text(self) -> str:
        """ "N functions", or "n/N functions" while a filter hides some."""
        if self.function_manager is None:
            return ""
        shown, total = self.row_count, self.total_count
        return f"{shown} functions" if shown == total else f"{shown}/{total} functions"

    #
    # Cells
    #

    def column_value(self, obj: FunctionTableEntry, col: int) -> Any:
        if col == self.INLINE_COL:
            return self.is_checked(obj, col)
        if col == self.NAME_COL:
            if not self.instance.project.am_none and self.instance.project.is_rust_binary and obj.name is not None:
                return rust_demangle(obj.name)
            name = obj.demangled_name
            if name is not None and name != obj.name and " " in name:
                name = get_cpp_function_name(name)
            return name
        if col == self.TAGS_COL:
            return obj.tags
        if col == self.ADDRESS_COL:
            return obj.addr
        if col == self.BINARY_COL:
            return obj.binary_name
        if col == self.SIZE_COL:
            return obj.size
        if col == self.BLOCKS_COL:
            return obj.number_of_blocks
        if col == self.COMPLEXITY_COL:
            return obj.cyclomatic_complexity
        return self.workspace.plugins.extract_func_column(obj, col - len(self.COLUMNS))[0]

    def column_text(self, obj: FunctionTableEntry, col: int) -> str:
        if col < len(self.COLUMNS):
            if col == self.INLINE_COL:
                return ""
            data = self.column_value(obj, col)
            if col == self.ADDRESS_COL:
                return f"{data:x}"
            if col == self.TAGS_COL:
                return tags_display_string(data)
            return str(data)
        return self.workspace.plugins.extract_func_column(obj, col - len(self.COLUMNS))[1]

    def style_key(self, obj: FunctionTableEntry, col: int) -> str | None:
        key = function_style_key(obj)
        if obj.from_signature and self.workspace.plugins.func_style(obj) is None:
            key += " function_table_signature_bg_color"
        return key

    def explicit_style(self, obj: FunctionTableEntry, col: int) -> StyleSpec | None:
        color = neutral_color(self.workspace.plugins.func_style(obj))
        return StyleSpec(bg=color) if color is not None else None

    def is_checked(self, obj: FunctionTableEntry, col: int) -> bool:
        return any(getattr(f, "addr", None) == obj.addr for f in self.instance.functions_to_inline)

    def set_checked(self, row: int, col: int, checked: bool) -> bool:
        if col != self.INLINE_COL:
            return False
        func = self.function_at(row)
        if func is None:
            return False
        inline = self.instance.functions_to_inline
        for existing in [f for f in inline if getattr(f, "addr", None) == func.addr]:
            inline.discard(existing)
        if checked:
            # the decompiler looks the callee's Function up in this set
            inline.add(func)
        self.rows_changed(row, row)
        return True

    #
    # Filtering
    #

    _filter_from_scratch: bool = False

    def _can_refine(self) -> bool:
        if self._filter_from_scratch:
            self._filter_from_scratch = False
            return False
        return True

    def _accepts(self, obj: FunctionTableEntry) -> bool:
        if not self.show_alignment and obj.is_alignment:
            return False
        return super()._accepts(obj)

    def matches(self, obj: FunctionTableEntry, keyword: str) -> bool:
        """Whether the name, demangled name, address, tags, binary or a plugin column contains ``keyword``."""
        if not keyword:
            return True
        if obj.name is not None and keyword in obj.name.lower():
            return True
        demangled_name = obj.demangled_name
        if demangled_name and keyword in demangled_name.lower():
            return True
        if isinstance(obj.addr, int):
            if keyword in f"{obj.addr:x}":
                return True
            if keyword in f"{obj.addr:#x}":
                return True
        if obj.tags and keyword in ",".join(obj.tags).lower():
            return True
        if obj.binary_name and keyword in obj.binary_name.lower():
            return True
        for idx in range(self._plugin_column_count()):
            txt = self.workspace.plugins.extract_func_column(obj, idx)[1]
            if txt and keyword in txt.lower():
                return True
        return False

    #
    # Activation and the context menu
    #

    def on_activate(self, obj: FunctionTableEntry) -> None:
        if self.function_manager is None or self.on_select is None:
            return
        try:
            func = self.function_manager.get_by_addr(obj.addr)
        except KeyError:
            return
        self.on_select(func)

    def context_menu(self, rows: Sequence[int]) -> Menu | None:
        return function_context_menu(self.workspace, self.functions(rows))


def edit_function_comment(workspace, func: Function) -> None:
    """Ask for the function's header comment."""
    workspace.main_instance.annotations.set_kind(func.addr, CommentKind.FUNCTION)
    current = workspace.main_instance.kb.comments.get(func.addr, "") if workspace.main_instance.kb else ""

    def then(text: str | None) -> None:
        if text is not None:
            workspace.set_comment(func.addr, text, kind=CommentKind.FUNCTION)

    ask_text("Function comment", f"Comment for {func.name}:", str(current or ""), then)


def function_context_menu(workspace, funcs: Sequence[Function], edit_comment=None) -> Menu | None:
    """
    The context menu of the selected functions: their info, their comment and the plugins' entries.

    :param edit_comment:    What "Edit Function Comment..." does with the function; a prompt by default.
    """
    funcs = list(funcs)
    menu = Menu("Function")
    if funcs:
        do_edit = edit_comment if edit_comment is not None else (lambda f: edit_function_comment(workspace, f))
        menu.add(MenuEntry("Show Function Info", lambda: workspace.show_function_info(funcs[0])))
        menu.add(MenuEntry("Edit Function Comment...", lambda: do_edit(funcs[0])))
    for entry in workspace.plugins.build_context_menu_functions(funcs):
        menu.add(entry)
    return menu if menu.entries else None


class FunctionsPresenter(InstancePresenter):
    """The functions view: it reloads when the CFG changes, and opens a function in the disassembly view."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "left") -> None:
        super().__init__(workspace, "functions", instance, default_docking_position)
        self.base_caption = "Functions"
        self.model = FunctionTableModel(workspace, instance, on_select=self.select_function)
        self._last_known_func_addrs: set[int] = set()
        self._function_count: int | None = None
        self._selection_callbacks: list[Callable[..., Any]] = []
        container(self.instance.cfg).am_subscribe(self.reload)

    def close(self) -> None:
        container(self.instance.cfg).am_unsubscribe(self.reload)

    @property
    def keymap(self) -> Keymap:
        return table_keymap()

    @property
    def function_manager(self) -> FunctionManager | None:
        return self.model.function_manager

    def reload(self, **kwargs) -> None:  # pylint:disable=unused-argument
        kb = self.instance.kb
        if not container(self.instance.cfg).am_none and kb is not None:
            self.set_function_manager(kb.functions)
        else:
            # the project was closed (or no CFG yet): clear the table
            self.set_function_manager(None)

    def set_function_manager(self, function_manager: FunctionManager | None) -> None:
        self._function_count = len(function_manager) if function_manager is not None else 0
        self.model.load(function_manager)
        self._last_known_func_addrs = {f.addr for f in self.model.all_rows}

    def refresh(self) -> None:
        funcman = self.model.function_manager
        if funcman is None:
            return
        if self._function_count != len(funcman):
            added, removed = self._updated_functions(funcman)
            self.model.update(added, removed)
        else:
            self.model.rows_changed()
        self._function_count = len(self._last_known_func_addrs)

    def reset_cache_and_refresh(self) -> None:
        self.model.rows_changed()
        self.refresh()

    def _updated_functions(self, function_manager: FunctionManager) -> tuple[set[int], set[int]]:
        if len(self._last_known_func_addrs) == len(function_manager.function_addrs_set):
            return set(), set()
        new_func_addrs_set = function_manager.function_addrs_set.copy()
        added = new_func_addrs_set.difference(self._last_known_func_addrs)
        removed = self._last_known_func_addrs.difference(new_func_addrs_set)
        self._last_known_func_addrs = new_func_addrs_set
        return added, removed

    #
    # Filtering and selection
    #

    @property
    def show_alignment_functions(self) -> bool:
        return self.model.show_alignment

    def toggle_show_alignment_functions(self) -> None:
        self.model.set_show_alignment(not self.model.show_alignment)

    def filter(self, text: str) -> None:
        self.model.filter(text)

    def count_text(self) -> str:
        return self.model.count_text()

    def subscribe_func_select(self, callback: Callable[..., Any]) -> None:
        """Call ``callback(func=function)`` when a function is chosen in the table."""
        self._selection_callbacks.append(callback)

    def select_function(self, func: Function) -> None:
        """Open ``func``: in the views that show functions, or a disassembly view."""
        for callback in list(self._selection_callbacks):
            callback(func=func)
        self.workspace.on_function_selected(func=func)

    def jump_to_result(self, index: int = 0) -> None:
        """Open the function on row ``index`` of the filtered table, as Enter in the filter box does."""
        if 0 <= index < self.model.row_count:
            self.model.activate(index)
