"""The breakpoints view without a toolkit: the breakpoint list, and adding, editing and removing breakpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from angrmanagement.data.breakpoint import Breakpoint, BreakpointType

from .base import InstancePresenter
from .dialogs import apply_breakpoint, breakpoint_form
from .forms import ask_form
from .keymap import table_keymap
from .menus import Menu, MenuEntry, MenuSeparator
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from angrmanagement.data.breakpoint import BreakpointManager
    from angrmanagement.data.instance import Instance

    from .keymap import Keymap

BREAKPOINT_TYPE_NAMES = {BreakpointType.Execute: "Execute", BreakpointType.Read: "Read", BreakpointType.Write: "Write"}


class BreakpointsTableModel(ListTableModel[Breakpoint]):
    """The breakpoints of a breakpoint manager, in the order they were added."""

    COL_TYPE = 0
    COL_ADDR = 1
    COL_SIZE = 2
    COL_COMMENT = 3

    COLUMNS: ClassVar[list[Column]] = [
        Column("Type", 8),
        Column("Address", 12),
        Column("Size", 6),
        Column("Comment", stretch=True),
    ]
    Headers: ClassVar[list[str]] = [c.name for c in COLUMNS]

    def __init__(self, breakpoint_mgr: BreakpointManager, presenter: BreakpointsPresenter | None = None) -> None:
        super().__init__()
        self.breakpoint_mgr = breakpoint_mgr
        self.presenter = presenter
        self.breakpoint_mgr.breakpoints.am_subscribe(self._on_breakpoints_updated)
        self.reload()

    def shutdown(self) -> None:
        self.breakpoint_mgr.breakpoints.am_unsubscribe(self._on_breakpoints_updated)

    def reload(self) -> None:
        self.set_rows(list(self.breakpoint_mgr.breakpoints))

    def _on_breakpoints_updated(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self.reload()

    def column_text(self, obj: Breakpoint, col: int) -> str:
        if col == self.COL_TYPE:
            return BREAKPOINT_TYPE_NAMES.get(obj.type, "")
        if col == self.COL_ADDR:
            return f"{obj.addr:#08x}"
        if col == self.COL_SIZE:
            return f"{obj.size:#x}"
        if col == self.COL_COMMENT:
            return obj.comment
        return ""

    def on_activate(self, obj: Breakpoint) -> None:
        if self.presenter is not None:
            self.presenter.edit_breakpoint(obj)

    def context_menu(self, rows: Sequence[int]) -> Menu | None:
        if self.presenter is None:
            return None
        return self.presenter.breakpoints_menu(self.objects(rows))


def parse_breakpoint(text: str) -> tuple[BreakpointType, int, int] | None:
    """
    Parse ``[execute|read|write] ADDRESS [SIZE]``, the prompt answer of a frontend without a breakpoint dialog.
    Numbers are in hex with or without ``0x``. Returns None for anything else.
    """
    parts = text.split()
    if not parts:
        return None
    types = {"execute": BreakpointType.Execute, "read": BreakpointType.Read, "write": BreakpointType.Write}
    type_ = BreakpointType.Execute
    if parts[0].lower() in types:
        type_ = types[parts[0].lower()]
        parts = parts[1:]
    if not 1 <= len(parts) <= 2:
        return None
    try:
        addr = int(parts[0], 16)
        size = int(parts[1], 16) if len(parts) == 2 else 1
    except ValueError:
        return None
    return type_, addr, size


class BreakpointsPresenter(InstancePresenter):
    """The breakpoints view."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "breakpoints", instance, default_docking_position)
        self.base_caption = "Breakpoints"
        self.breakpoint_mgr = instance.breakpoint_mgr
        self.model = BreakpointsTableModel(self.breakpoint_mgr, self)

    def close(self) -> None:
        self.model.shutdown()

    @property
    def keymap(self) -> Keymap:
        return table_keymap()

    def ask_breakpoint(self, bp: Breakpoint, then: Callable[[bool], None]) -> None:
        """
        Let the user edit ``bp`` in place in the Edit Breakpoint form, then call ``then`` with whether they confirmed.
        The Qt view uses its breakpoint dialog, which checks the address and size the same way.
        """

        def on_answer(values: dict[str, Any] | None) -> None:
            if values is None:
                then(False)
                return
            apply_breakpoint(bp, values, self.instance)
            then(True)

        ask_form(breakpoint_form(bp, self.instance), on_answer)

    def new_breakpoint(self) -> None:
        bp = Breakpoint(BreakpointType.Execute, 0)

        def then(confirmed: bool) -> None:
            if confirmed:
                self.breakpoint_mgr.add_breakpoint(bp)

        self.ask_breakpoint(bp, then)

    def edit_breakpoint(self, breakpoint_: Breakpoint) -> None:
        def then(confirmed: bool) -> None:
            if confirmed:
                self.breakpoint_mgr.breakpoints.am_event()

        self.ask_breakpoint(breakpoint_, then)

    def remove_breakpoints(self, breakpoints: Sequence[Breakpoint]) -> None:
        for b in list(breakpoints):
            self.breakpoint_mgr.remove_breakpoint(b)

    def breakpoints_menu(self, breakpoints: Sequence[Breakpoint], edit=None, new=None) -> Menu:
        """
        Edit, remove or add breakpoints.

        :param edit:    What "Edit breakpoint" does; :meth:`edit_breakpoint` by default.
        :param new:     What "New breakpoint" does; :meth:`new_breakpoint` by default.
        """
        breakpoints = list(breakpoints)
        do_edit = edit if edit is not None else self.edit_breakpoint
        menu = Menu("")
        if breakpoints:
            if len(breakpoints) == 1:
                menu.add(MenuEntry("Edit breakpoint", lambda: do_edit(breakpoints[0])))
            menu.add(
                MenuEntry(
                    "Remove breakpoint" + ("s" if len(breakpoints) > 1 else ""),
                    lambda: self.remove_breakpoints(breakpoints),
                )
            )
            menu.add(MenuSeparator())
        menu.add(MenuEntry("New breakpoint", new if new is not None else self.new_breakpoint))
        return menu
