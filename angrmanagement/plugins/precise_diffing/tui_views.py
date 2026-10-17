"""
The precise diff's two views for the terminal: the disassembly and the pseudocode of the revised binary, the
terminal's own views over the diff instance, as diff_view.py makes them for Qt.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angrmanagement.tui.views.code import CodeTuiView
from angrmanagement.tui.views.disassembly import DisassemblyTuiView

if TYPE_CHECKING:
    from collections.abc import Callable


class DiffDisassemblyTuiView(DisassemblyTuiView):
    """
    The revised binary's disassembly. Its addresses differ from the original's, so it follows the original view's
    function through the plugin rather than the synchronized cursor.
    """

    def __init__(self, workspace, default_docking_position: str, instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        self.category = "diff"
        self.presenter.base_caption = "Precise Diff"

    def set_synchronized_cursor_address(self, address: int | None) -> None:
        pass

    def decompile_current_function(self) -> None:
        """Decompile into the diff's pseudocode view, as the Qt DiffDisassemblyView does."""
        func = self.presenter.function.am_obj
        if func is None:
            return
        try:
            curr_ins = next(iter(self.presenter.infodock.selected_insns))
        except StopIteration:
            curr_ins = None
        view = self.workspace._get_or_create_view("pseudocode_diff", DiffCodeTuiView)
        view.function.am_obj = func
        view.function.am_event(focus=True, focus_addr=curr_ins)


class DiffCodeTuiView(CodeTuiView):
    """The revised binary's pseudocode; ``after_ready`` runs whenever its text changes, to colour the diff."""

    def __init__(
        self, workspace, default_docking_position: str, instance, after_ready: Callable[..., Any] | None = None
    ) -> None:
        super().__init__(workspace, default_docking_position, instance)
        self.category = "pseudocode_diff"
        self.presenter.base_caption = "Precise Diff Pseudocode"
        self.after_ready = after_ready
        self.presenter.codegen.am_subscribe(self._diff_ready)

    def _diff_ready(self, **_kwargs) -> None:
        if self.after_ready is not None:
            self.after_ready()


__all__ = ["DiffCodeTuiView", "DiffDisassemblyTuiView"]
