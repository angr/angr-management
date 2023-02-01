# pylint:disable=unused-private-member
import logging
from typing import TYPE_CHECKING, Any, Callable, Generator, Iterable, List, Optional, Tuple, Type, Union

_l = logging.getLogger(__name__)

if TYPE_CHECKING:
    from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass
    from angr.sim_manager import SimulationManager
    from PySide6.QtGui import QColor, QIcon, QPainter
    from PySide6.QtWidgets import QGraphicsSceneMouseEvent

    from angrmanagement.config.config_entry import ConfigurationEntry
    from angrmanagement.ui.views import code_view, disassembly_view
    from angrmanagement.ui.widgets.qblock import QBlock
    from angrmanagement.ui.widgets.qinst_annotation import QInstructionAnnotation
    from angrmanagement.ui.widgets.qinstruction import QInstruction
    from angrmanagement.ui.workspace import Workspace

# pylint: disable=no-self-use,unused-argument


class BasePlugin:
    """
    Implements the base class for all angr management plugins.
    """

    # Override DISPLAY_NAME to specify a human-readable name for your plugin
    DISPLAY_NAME = None
    REQUIRE_WORKSPACE = True
    __i_hold_this_abstraction_token = True

    def __init__(self, workspace):
        self.workspace: Optional["Workspace"] = workspace
        _l.info("Loaded plugin %s", self.__class__.__name__)

        # valid things that we want you do be able to do in __init__:
        # - set callbacks for object containers
        # ... so then all of those should be undone in teardown

    def teardown(self):
        pass

    @classmethod
    def get_display_name(cls):
        display_name = getattr(cls, "DISPLAY_NAME", None)
        if not display_name:
            return cls.__name__
        return display_name

    #
    # Generic callbacks
    #

    def status_bar_permanent_widgets(self) -> Optional[Generator]:
        """
        Yields all widgets that should be added to the right side of the status bar of the main window.
        """
        return None

    def on_workspace_initialized(self, workspace: "Workspace"):
        """
        A handler that is called right after a workspace is initialized.
        """

    def angrdb_store_entries(self):
        """
        Yields all entries (key-value pairs) that should be persisted inside angrDb.
        :return:
        """
        return None

    def angrdb_load_entry(self, key: str, value: str) -> None:
        """
        Called for each entry (key-value pair) that is persisted in angrDb.

        :param key:     Key of the entry.
        :param value:   Value of the entry.
        """

    #
    # UI Callbacks
    #

    def color_insn(self, addr, selected) -> Optional["QColor"]:
        return None

    def color_block(self, addr) -> Optional["QColor"]:
        return None

    def color_func(self, func) -> Optional["QColor"]:
        return None

    def draw_insn(self, qinsn: "QInstruction", painter: "QPainter"):
        pass

    def draw_block(self, qblock: "QBlock", painter: "QPainter"):
        pass

    def instrument_disassembly_view(self, dview: "disassembly_view.DisassemblyView"):
        pass

    def instrument_code_view(self, cview: "code_view.CodeView"):
        pass

    def handle_click_insn(self, qinsn, event: "QGraphicsSceneMouseEvent"):
        return False

    def handle_click_block(self, qblock, event: "QGraphicsSceneMouseEvent"):
        return False

    def handle_raise_view(self, view):
        pass

    # iterable of tuples (icon, tooltip)
    TOOLBAR_BUTTONS: List[Tuple["QIcon", str]] = []

    def handle_click_toolbar(self, idx):
        pass

    # Iterable of button texts
    MENU_BUTTONS: List[str] = []

    def handle_click_menu(self, idx):
        pass

    # Iterable of column names
    FUNC_COLUMNS: List[str] = []

    def extract_func_column(self, func, idx) -> Tuple[Any, str]:
        # should return a tuple of the sortable column data and the rendered string
        return 0, ""

    def build_context_menu_insn(self, item) -> Iterable[Union[None, Tuple[str, Callable]]]:
        """
        Use None to insert a MenuSeparator(). The tuples are: (menu entry text, callback)
        """
        return []

    def build_context_menu_block(self, item) -> Iterable[Union[None, Tuple[str, Callable]]]:
        """
        Use None to insert a MenuSeparator(). The tuples are: (menu entry text, callback)
        """
        return []

    def build_context_menu_node(self, node) -> Iterable[Union[None, Tuple[str, Callable]]]:
        """
        Use None to insert a MenuSeparator(). The tuples are: (menu entry text, callback)
        """
        return []

    def build_context_menu_functions(self, funcs) -> Iterable[Union[None, Tuple[str, Callable]]]:
        return []

    def build_qblock_annotations(self, qblock: "QBlock") -> Iterable["QInstructionAnnotation"]:
        return []

    # Iterable of URL actions
    URL_ACTIONS: List[str] = []

    def handle_url_action(self, action, kwargs):
        pass

    def step_callback(self, simgr: "SimulationManager"):
        pass

    # Custom configuration entries
    CONFIG_ENTRIES: List["ConfigurationEntry"] = []

    #
    # Decompiler Callbacks
    #

    OPTIMIZATION_PASSES: List[Tuple[Type["OptimizationPass"], bool]] = []

    def handle_stack_var_renamed(self, func, offset, old_name, new_name):
        return False

    def handle_stack_var_retyped(self, func, offset, old_type, new_type):
        return False

    def handle_func_arg_renamed(self, func, offset, old_name, new_name):
        return False

    def handle_func_arg_retyped(self, func, offset, old_type, new_type):
        return False

    def handle_global_var_renamed(self, address, old_name, new_name):
        return False

    def handle_global_var_retyped(self, address, old_type, new_type):
        return False

    def handle_other_var_renamed(self, var, old_name, new_name):
        return False

    def handle_other_var_retyped(self, var, old_type, new_type):
        return False

    def handle_function_renamed(self, func, old_name, new_name):
        return False

    def handle_function_retyped(self, func, old_type, new_type):
        return False

    def handle_comment_changed(self, address, old_cmt, new_cmt, created: bool, decomp: bool):
        return False

    def handle_struct_changed(self, old_struct, new_struct):
        return False

    def decompile_callback(self, func):
        """
        A callback that is called *right after* the decompiler is run on a function. You can access the current codegen
        with ``self.workspace.instance.kb.structured_code[(func.addr, 'pseudocode')]``
        :param func:        angr Function that was just decompiled
        """

    def handle_project_save(self, file_name: str):
        """
        A handler to notify plugins whenever the project has been saved by the user.

        @param file_name:       Name in which project is saved as.
        @return:
        """

    def handle_project_initialization(self):
        """
        A handler to perform any initialization when a new project is loaded
        """
