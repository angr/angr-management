import logging
from typing import Optional, Tuple, Callable, Iterator, List, Any, Union, TYPE_CHECKING
from PySide2.QtGui import QColor, QPainter
from PySide2.QtGui import QIcon
from PySide2.QtWidgets import QGraphicsSceneMouseEvent

from angrmanagement.ui.widgets.qblock import QBlock
from angrmanagement.ui.widgets.qinstruction import QInstruction

_l = logging.getLogger(__name__)

if TYPE_CHECKING:
    from angrmanagement.ui.views import disassembly_view, code_view


# pylint: disable=no-self-use,unused-argument

class BasePlugin:
    REQUIRE_WORKSPACE = True
    __i_hold_this_abstraction_token = True

    def __init__(self, workspace):

        from angrmanagement.ui.workspace import Workspace

        self.workspace: Optional[Workspace] = workspace
        _l.info("Loaded plugin %s", self.__class__.__name__)

        # valid things that we want you do be able to do in __init__:
        # - set callbacks for object containers
        # ... so then all of those should be undone in teardown

    def teardown(self):
        pass

    @classmethod
    def get_display_name(cls: 'BasePlugin'):
        return getattr(cls, 'DISPLAY_NAME', cls.__name__)

    #
    # UI Callbacks
    #

    def color_insn(self, addr, selected) -> Optional[QColor]:
        return None

    def color_block(self, addr) -> Optional[QColor]:
        return None

    def color_func(self, func) -> Optional[QColor]:
        return None

    def draw_insn(self, qinsn: QInstruction, painter: QPainter):
        pass

    def draw_block(self, qblock: QBlock, painter: QPainter):
        pass

    def instrument_disassembly_view(self, dview: 'disassembly_view.DisassemblyView'):
        pass

    def instrument_code_view(self, cview: 'code_view.CodeView'):
        pass

    def handle_click_insn(self, qinsn, event: QGraphicsSceneMouseEvent):
        return False

    def handle_click_block(self, qblock, event: QGraphicsSceneMouseEvent):
        return False

    # iterable of tuples (icon, tooltip)
    TOOLBAR_BUTTONS = []  # type: List[Tuple[QIcon, str]]

    def handle_click_toolbar(self, idx):
        pass

    # Iterable of button texts
    MENU_BUTTONS = []  # type: List[str]

    def handle_click_menu(self, idx):
        pass

    # Iterable of column names
    FUNC_COLUMNS = []  # type: List[str]

    def extract_func_column(self, func, idx) -> Tuple[Any, str]:
        # should return a tuple of the sortable column data and the rendered string
        return 0, ''

    def build_context_menu_insn(self, item) -> Iterator[Union[None, Tuple[str, Callable]]]:
        """
        Use None to insert a MenuSeparator(). The tuples are: (menu entry text, callback)
        """
        return []

    def build_context_menu_block(self, item) -> Iterator[Union[None, Tuple[str, Callable]]]:
        """
        Use None to insert a MenuSeparator(). The tuples are: (menu entry text, callback)
        """
        return []

    def build_context_menu_node(self, node) -> Iterator[Union[None, Tuple[str, Callable]]]:
        """
        Use None to insert a MenuSeparator(). The tuples are: (menu entry text, callback)
        """
        return []


    def build_context_menu_function(self, func) -> Iterator[Union[None, Tuple[str, Callable]]]:
        return []

    # Iterable of URL actions
    URL_ACTIONS: List[str] = []

    def handle_url_action(self, action, kwargs):
        pass

    #
    # Decompiler Callbacks
    #

    def handle_variable_rename(self, func, offset: int, old_name: str, new_name: str):
        """
        A handler that is called *right before* function stack variable is renamed. Note: this does not directly
        allow you to intercept the call and change the results of the change. This handler is only intended to be
        used to observe the actuall changing and act accordingly after.

        @param func:        angr Function the variable is changed in
        @param offset:      the offset of the stack variable
        @param old_name:    name before change
        @param new_name:    name after change
        @return:
        """
        return False

    def handle_function_rename(self, func, old_name: str, new_name: str):
        """
        A handler that is called *right before* a functions name is renamed. See the Note in handle_variable_rename
        about how this should only be for observance.

        @param func:        angr Function that is being renamed
        @param old_name:    name before change
        @param new_name:    name after change
        @return:
        """
        return False

    def handle_comment_changed(self, func, addr: int, new: bool, decomp: bool):
        """
        A handler that is called for a variety of reasons related to changing and making a comment. All are called
        right before the operation happens:
        1. A comment is made for the first time
        2. A comment is changed

        `new` bool is true when it is being created for the first time.

        In additon to those two cases, each comment can either be changed in the decompilation view or the
        dissassembly view, specified by the `decomp` boolean. If true, the comment is changed in the decompilation
        view.

        @param func:        Function the comment is in
        @param addr:        Address in func that comment is on
        @param new:         T if a new comment
        @param decomp:      T if comment in decompilation view
        @return:
        """

        return False

