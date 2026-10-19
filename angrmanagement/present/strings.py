"""The strings view without a toolkit: the strings the CFG found, by function, with a wildcard or regex filter."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort

from angrmanagement.utils import filter_string_for_display

from .base import InstancePresenter
from .keymap import strings_keymap
from .tables import Column, ListTableModel, compile_filter

if TYPE_CHECKING:
    from collections.abc import Callable

    from angr.knowledge_plugins import Function
    from angr.knowledge_plugins.cfg.memory_data import MemoryData

    from angrmanagement.data.instance import Instance

    from .keymap import Keymap

_ENCODINGS = {MemoryDataSort.String: "utf-8", MemoryDataSort.UnicodeString: "utf_16_le"}


def decoded_string_content(md: MemoryData) -> str:
    """The text of a string memory data entry; it must have content."""
    content = md.content if md.content is not None else b""
    return content.decode(_ENCODINGS.get(md.sort or "", "utf-8"))


class StringsTableModel(ListTableModel["MemoryData"]):
    """
    The string memory data of a CFG, optionally only those a function references. The filter applies to the string
    column, as a wildcard pattern or, with :meth:`set_filter`, a regular expression.
    """

    ADDRESS_COL = 0
    SIZE_COL = 1
    LENGTH_COL = 2
    STRING_COL = 3

    COLUMNS: ClassVar[list[Column]] = [
        Column("Address", 10),
        Column("Size (Bytes)", 12),
        Column("Length", 7),
        Column("String", stretch=True),
    ]
    HEADER: ClassVar[list[str]] = [c.name for c in COLUMNS]

    def __init__(self, cfg=None, func=None) -> None:
        super().__init__()
        self._cfg = cfg
        self._function = func
        self._xrefs = None
        self._predicate = compile_filter(None)
        self.on_select: Callable[[MemoryData], None] | None = None

    #
    # What to list
    #

    @property
    def cfg(self):
        return self._cfg

    @cfg.setter
    def cfg(self, v) -> None:
        self._cfg = v
        self.load()

    @property
    def xrefs(self):
        return self._xrefs

    @xrefs.setter
    def xrefs(self, v) -> None:
        self._xrefs = v
        self.load()

    @property
    def function(self):
        return self._function

    @function.setter
    def function(self, v) -> None:
        self._function = v
        self.load()

    @property
    def values(self) -> list[MemoryData]:
        return self.all_rows

    def load(self) -> None:
        self.set_rows(self._get_all_string_memory_data())

    def _get_all_string_memory_data(self) -> list[MemoryData]:
        lst = []
        # the instance hands over its CFG container, which is empty until the CFG is recovered (a view restored with
        # the saved tabs can open before that); the view reloads when the CFG arrives
        cfg = self._cfg
        if cfg is None or getattr(cfg, "am_none", False):
            return lst
        for v in cfg.memory_data.values():
            if v.sort in {MemoryDataSort.String, MemoryDataSort.UnicodeString}:
                if self._function is None:
                    lst.append(v)
                elif self._xrefs is not None and v.addr in self._xrefs.xrefs_by_dst:
                    for xref in self._xrefs.xrefs_by_dst[v.addr]:
                        if xref.block_addr in self._function.block_addrs_set:
                            lst.append(v)
                            break
        return lst

    #
    # Filtering
    #

    def set_filter(self, pattern: str | re.Pattern | None, regex: bool = False) -> None:
        """Show the strings that match ``pattern``, a wildcard, or a regular expression with ``regex``."""
        self._predicate = compile_filter(pattern, regex=regex)
        text = pattern.pattern if isinstance(pattern, re.Pattern) else (pattern or "")
        super().filter(str(text))

    def filter(self, text: str) -> None:
        """Filter by the wildcard ``text``."""
        self.set_filter(text)

    def _can_refine(self) -> bool:  # pylint:disable=no-self-use
        # a pattern that contains the previous one does not match fewer strings in general
        return False

    def _accepts(self, obj: MemoryData) -> bool:
        if not self._filter_text:
            return True
        return self._predicate(self.column_text(obj, self.STRING_COL))

    #
    # Cells
    #

    def column_value(self, obj: MemoryData, col: int) -> Any:
        if col == self.ADDRESS_COL:
            return obj.addr
        if col == self.SIZE_COL:
            return obj.size
        if col == self.LENGTH_COL:
            return len(decoded_string_content(obj)) if obj.content is not None else "<ERROR>"
        if col == self.STRING_COL:
            return filter_string_for_display(decoded_string_content(obj)) if obj.content is not None else "<ERROR>"
        return None

    def column_text(self, obj: MemoryData, col: int) -> str:
        data = self.column_value(obj, col)
        if col == self.ADDRESS_COL and isinstance(data, int):
            return f"{data:x}"
        return "" if data is None else str(data)

    def on_activate(self, obj: MemoryData) -> None:
        if self.on_select is not None:
            self.on_select(obj)


class StringsPresenter(InstancePresenter):
    """The strings view: the table, the function it is narrowed to, and what choosing a string does."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "strings", instance, default_docking_position)
        self.base_caption = "Strings"
        self.model = StringsTableModel()
        self.model.on_select = self.select_string
        self.selected_function: Function | None = None

    @property
    def keymap(self) -> Keymap:
        return strings_keymap()

    def reload(self) -> None:
        if self.instance.kb is None:
            return
        self.model._cfg = self.instance.cfg  # pylint:disable=protected-access
        self.model._xrefs = self.instance.project.kb.xrefs  # pylint:disable=protected-access
        self.model._function = self.selected_function  # pylint:disable=protected-access
        self.model.load()

    def select_function(self, function: Function | None) -> None:
        """Narrow the list to the strings ``function`` references; all strings for None."""
        self.selected_function = function
        self.reload()

    def set_filter(self, pattern: str, regex: bool = False) -> bool:
        """
        Filter the strings by ``pattern``. Returns False, and leaves the filter as it was, for an invalid regular
        expression.
        """
        if regex:
            try:
                compiled = re.compile(pattern)
            except re.error:
                return False
            self.model.set_filter(compiled)
        else:
            self.model.set_filter(pattern)
        return True

    def select_string(self, s: MemoryData) -> None:
        """Show the string in the disassembly view."""
        if len(self.workspace.view_manager.views_by_category["disassembly"]) == 1:
            disasm_view = self.workspace.view_manager.first_view_in_category("disassembly")
        else:
            disasm_view = self.workspace.view_manager.current_view_in_category("disassembly")
        if disasm_view is not None:
            disasm_view.jump_to(s.addr)
            select_label = getattr(disasm_view, "select_label", None)
            if select_label is not None:
                select_label(s.addr)
            self.workspace.view_manager.raise_view(disasm_view)
