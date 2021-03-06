from angrmanagement.plugins import BasePlugin
from typing import List, Iterator, Union, Tuple, Callable

class SamplePlugin(BasePlugin):
    def __init__(self, workspace):
        super().__init__(workspace)

        workspace.instance.register_container('bookmarks', lambda: [], List[int], 'Bookmarked addresses')

    MENU_BUTTONS = ('Add Bookmark',)

    def build_context_menu_node(self, node) -> Iterator[Union[None, Tuple[str, Callable]]]:
        yield ("owo", [("uwu", lambda: None), ("o_O", lambda: None)])