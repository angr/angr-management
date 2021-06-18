from angrmanagement.plugins import BasePlugin
from typing import List, Iterator, Union, Tuple, Callable

class SamplePlugin(BasePlugin):
    def __init__(self, workspace):
        super().__init__(workspace)

        workspace.instance.register_container('bookmarks', lambda: [], List[int], 'Bookmarked addresses')

    MENU_BUTTONS = ('Add Bookmark',)

    def build_context_menu_function(self, funcs): # pylint: disable=unused-argument
        yield ("owo", [("uwu", lambda: None), ("o_O", lambda: None)])
