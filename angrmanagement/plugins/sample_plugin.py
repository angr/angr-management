from typing import TYPE_CHECKING, Iterator, List

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.widgets.qinst_annotation import QInstructionAnnotation, QPassthroughCount

if TYPE_CHECKING:
    from angr.sim_manager import SimulationManager

    from angrmanagement.ui.widgets.qblock import QBlock


class SamplePlugin(BasePlugin):
    def __init__(self, workspace):
        super().__init__(workspace)

        workspace.main_instance.register_container("bookmarks", lambda: [], List[int], "Bookmarked addresses")

    MENU_BUTTONS = ("Add Bookmark",)

    def build_context_menu_functions(self, funcs):  # pylint: disable=unused-argument
        yield ("owo", [("uwu", lambda: None), ("o_O", lambda: None)])

    def step_callback(self, simgr: SimulationManager):
        print("Active States: %s" % simgr)

    def build_qblock_annotations(self, qblock: QBlock) -> Iterator[QInstructionAnnotation]:
        return [QPassthroughCount(qblock.addr, "entry")]
