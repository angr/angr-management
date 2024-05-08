# pylint:disable=unused-private-member
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

_l = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterable

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

    def __init__(self, workspace: Workspace) -> None:
        self.workspace: Workspace | None = workspace
        _l.info("Loaded plugin %s", self.__class__.__name__)

        # valid things that we want you do be able to do in __init__:
        # - set callbacks for object containers
        # ... so then all of those should be undone in teardown

    def teardown(self) -> None:
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

    def status_bar_permanent_widgets(self) -> Generator | None:
        """
        Yields all widgets that should be added to the right side of the status bar of the main window.
        """
        return None

    def on_workspace_initialized(self, workspace: Workspace) -> None:
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

    def color_insn(self, addr: int, selected, disasm_view) -> QColor | None:
        return None

    def color_block(self, addr: int) -> QColor | None:
        return None

    def color_func(self, func) -> QColor | None:
        return None

    def draw_insn(self, qinsn: QInstruction, painter: QPainter) -> None:
        pass

    def draw_block(self, qblock: QBlock, painter: QPainter) -> None:
        pass

    def instrument_disassembly_view(self, dview: disassembly_view.DisassemblyView) -> None:
        pass

    def instrument_code_view(self, cview: code_view.CodeView) -> None:
        pass

    def handle_click_insn(self, qinsn, event: QGraphicsSceneMouseEvent) -> bool:
        return False

    def handle_click_block(self, qblock, event: QGraphicsSceneMouseEvent) -> bool:
        return False

    def handle_raise_view(self, view) -> None:
        pass

    # iterable of tuples (icon, tooltip)
    TOOLBAR_BUTTONS: list[tuple[QIcon, str]] = []

    def handle_click_toolbar(self, idx: int) -> None:
        pass

    # Iterable of button texts
    MENU_BUTTONS: list[str] = []

    def handle_click_menu(self, idx: int) -> None:
        pass

    # Iterable of column names
    FUNC_COLUMNS: list[str] = []

    def extract_func_column(self, func, idx: int) -> tuple[Any, str]:
        # should return a tuple of the sortable column data and the rendered string
        return 0, ""

    def build_context_menu_insn(self, item) -> Iterable[None | tuple[str, Callable]]:
        """
        Use None to insert a MenuSeparator(). The tuples are: (menu entry text, callback)
        """
        return []

    def build_context_menu_block(self, item) -> Iterable[None | tuple[str, Callable]]:
        """
        Use None to insert a MenuSeparator(). The tuples are: (menu entry text, callback)
        """
        return []

    def build_context_menu_node(self, node) -> Iterable[None | tuple[str, Callable]]:
        """
        Use None to insert a MenuSeparator(). The tuples are: (menu entry text, callback)
        """
        return []

    def build_context_menu_functions(self, funcs) -> Iterable[None | tuple[str, Callable]]:
        return []

    def build_qblock_annotations(self, qblock: QBlock) -> Iterable[QInstructionAnnotation]:
        return []

    # Iterable of URL actions
    URL_ACTIONS: list[str] = []

    def handle_url_action(self, action, kwargs) -> None:
        pass

    def step_callback(self, simgr: SimulationManager) -> None:
        pass

    # Custom configuration entries
    CONFIG_ENTRIES: list[ConfigurationEntry] = []

    #
    # Decompiler Callbacks
    #

    OPTIMIZATION_PASSES: list[tuple[type[OptimizationPass], bool]] = []

    def handle_stack_var_renamed(self, func, offset: int, old_name: str, new_name: str) -> bool:
        return False

    def handle_stack_var_retyped(self, func, offset: int, old_type, new_type) -> bool:
        return False

    def handle_func_arg_renamed(self, func, offset: int, old_name: str, new_name: str) -> bool:
        return False

    def handle_func_arg_retyped(self, func, offset: int, old_type, new_type) -> bool:
        return False

    def handle_global_var_renamed(self, address, old_name: str, new_name: str) -> bool:
        return False

    def handle_global_var_retyped(self, address, old_type, new_type) -> bool:
        return False

    def handle_other_var_renamed(self, var, old_name: str, new_name: str) -> bool:
        return False

    def handle_other_var_retyped(self, var, old_type, new_type) -> bool:
        return False

    def handle_function_renamed(self, func, old_name: str, new_name: str) -> bool:
        return False

    def handle_function_retyped(self, func, old_type, new_type) -> bool:
        return False

    def handle_comment_changed(self, address, old_cmt, new_cmt, created: bool, decomp: bool) -> bool:
        return False

    def handle_struct_changed(self, old_struct, new_struct) -> bool:
        return False

    def decompile_callback(self, func) -> None:
        """
        A callback that is called *right after* the decompiler is run on a function. You can access the current codegen
        with ``self.workspace.instance.kb.structured_code[(func.addr, 'pseudocode')]``
        :param func:        angr Function that was just decompiled
        """

    def handle_project_save(self, file_name: str) -> None:
        """
        A handler to notify plugins whenever the project has been saved by the user.

        @param file_name:       Name in which project is saved as.
        @return:
        """

    def handle_project_initialization(self) -> None:
        """
        A handler to perform any initialization when a new project is loaded
        """
