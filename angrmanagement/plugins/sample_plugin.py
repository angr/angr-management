from angrmanagement.ui.widgets.qinst_annotation import QInstructionAnnotation, QPassthroughCount
from angrmanagement.ui.widgets.qblock import QBlock
from angrmanagement.plugins import BasePlugin
from typing import List, Iterator


class SamplePlugin(BasePlugin):
    def __init__(self, workspace):
        super().__init__(workspace)

        workspace.instance.register_container('bookmarks', lambda: [], List[int], 'Bookmarked addresses')

    MENU_BUTTONS = ('Add Bookmark',)

    def build_context_menu_functions(self, funcs): # pylint: disable=unused-argument
        yield ("owo", [("uwu", lambda: None), ("o_O", lambda: None)])

    def build_qblock_annotations(self, qblock: QBlock) -> Iterator[QInstructionAnnotation]:
        return [
            QPassthroughCount(qblock.addr,"entry")
        ]
