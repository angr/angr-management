import logging
from typing import Optional, Tuple, Callable, Iterator, List, Any, Union, TYPE_CHECKING
from PySide2.QtGui import QColor, QPainter
from PySide2.QtGui import QIcon
from PySide2.QtWidgets import QGraphicsSceneMouseEvent
from angr.sim_manager import SimulationManager

from angrmanagement.ui.widgets.qblock import QBlock
from angrmanagement.ui.widgets.qinstruction import QInstruction

_l = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ..ui.views import disassembly_view, code_view
    from ..ui.workspace import Workspace

# pylint: disable=no-self-use,unused-argument

class BasePlugin:
    REQUIRE_WORKSPACE = True
    __i_hold_this_abstraction_token = True

    def __init__(self, workspace):
        self.workspace: 'Optional[Workspace]' = workspace
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
    # Callbacks
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

    def step_callback(self, simgr:SimulationManager):
        pass
