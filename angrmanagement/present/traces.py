"""The traces view without a toolkit: the loaded traces, which one is current, and removing them."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from .base import InstancePresenter, container
from .keymap import table_keymap
from .menus import Menu, MenuEntry
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from collections.abc import Sequence

    from angrmanagement.data.instance import Instance
    from angrmanagement.data.trace import Trace

    from .keymap import Keymap


class TracesTableModel(ListTableModel["Trace"]):
    """The instance's traces; the current one says so."""

    COL_SOURCE = 0

    COLUMNS: ClassVar[list[Column]] = [Column("Source", stretch=True)]
    Headers: ClassVar[list[str]] = [c.name for c in COLUMNS]

    def __init__(self, instance: Instance, presenter: TracesPresenter | None = None) -> None:
        super().__init__()
        self.instance = instance
        self.presenter = presenter
        container(self.instance.current_trace).am_subscribe(self._on_traces_updated)
        container(self.instance.traces).am_subscribe(self._on_traces_updated)
        self.reload()

    def shutdown(self) -> None:
        container(self.instance.current_trace).am_unsubscribe(self._on_traces_updated)
        container(self.instance.traces).am_unsubscribe(self._on_traces_updated)

    def reload(self) -> None:
        self.set_rows(list(container(self.instance.traces)))

    def _on_traces_updated(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self.reload()

    def column_text(self, obj: Trace, col: int) -> str:
        if col == self.COL_SOURCE:
            current = container(self.instance.current_trace).am_obj is obj
            return obj.source + (" (Current)" if current else "")
        return ""

    def context_menu(self, rows: Sequence[int]) -> Menu | None:
        if self.presenter is None:
            return None
        return self.presenter.traces_menu(self.objects(rows))


class TracesPresenter(InstancePresenter):
    """The traces view."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "traces", instance, default_docking_position)
        self.base_caption = "Traces"
        self.model = TracesTableModel(instance, self)

    def close(self) -> None:
        self.model.shutdown()

    @property
    def keymap(self) -> Keymap:
        return table_keymap()

    def remove_traces(self, traces: Sequence[Trace]) -> None:
        for trace in list(traces):
            self.workspace.remove_trace(trace)

    def traces_menu(self, traces: Sequence[Trace]) -> Menu | None:
        """Make the selected trace current, or remove the selected traces."""
        traces = list(traces)
        if not traces:
            return None
        menu = Menu("")
        if len(traces) == 1 and not self.workspace.is_current_trace(traces[0]):
            menu.add(MenuEntry("Use as current trace", lambda: self.workspace.set_current_trace(traces[0])))
        menu.add(MenuEntry("Remove trace" + ("s" if len(traces) > 1 else ""), lambda: self.remove_traces(traces)))
        return menu
