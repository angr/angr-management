from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.widgets.qinst_annotation import QInstructionAnnotation, QPassthroughCount

if TYPE_CHECKING:
    from collections.abc import Iterator

    from angr.sim_manager import SimulationManager

    from angrmanagement.ui.widgets.qblock import QBlock
    from angrmanagement.ui.workspace import Workspace


class SamplePlugin(BasePlugin):
    def __init__(self, workspace: Workspace) -> None:
        super().__init__(workspace)

        workspace.main_instance.register_container("bookmarks", list, list[int], "Bookmarked addresses")

    MENU_BUTTONS = ("Add Bookmark",)

    def build_context_menu_functions(self, funcs):  # pylint: disable=unused-argument
        yield ("owo", [("uwu", lambda: None), ("o_O", lambda: None)])

    def step_callback(self, simgr: SimulationManager) -> None:
        print(f"Active States: {simgr}")

    def build_qblock_annotations(self, qblock: QBlock) -> Iterator[QInstructionAnnotation]:
        return [QPassthroughCount(qblock.addr, "entry")]
