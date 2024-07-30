from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import angr
from angr.analyses.disassembly import Instruction
from angr.block import Block
from angr.knowledge_base import KnowledgeBase
from angr.knowledge_plugins import Function
from cle import SymbolType

from angrmanagement.data.breakpoint import Breakpoint, BreakpointManager, BreakpointType
from angrmanagement.data.trace import Trace
from angrmanagement.errors import ContainerAlreadyRegisteredError
from angrmanagement.logic.debugger import DebuggerListManager, DebuggerManager

from .log import LogRecord, initialize
from .object_container import ObjectContainer

if TYPE_CHECKING:
    from collections.abc import Callable

    from .jobs import VariableRecoveryJob


_l = logging.getLogger(__name__)


class Instance:
    """
    An object to give access to normal angr project objects like a Project, CFG, and other analyses.
    """

    project: ObjectContainer
    cfg: angr.analyses.cfg.CFGBase | ObjectContainer
    cfb: angr.analyses.cfg.CFBlanket | ObjectContainer
    log: list[LogRecord] | ObjectContainer

    def __init__(self) -> None:
        # pylint:disable=import-outside-toplevel
        # delayed import
        from angrmanagement.ui.views.interaction_view import (
            BackslashTextProtocol,
            PlainTextProtocol,
            ProtocolInteractor,
            SavedInteraction,
        )

        self._live = False
        self.variable_recovery_job: VariableRecoveryJob | None = None
        self._analysis_configuration = None

        self.extra_containers = {}
        self._container_defaults = {}

        # where this binary is coming from - if it's loaded from a URL, then original_binary_path will be the URL
        self.original_binary_path = None
        # where this binary is now - if it's loaded from a URL, then binary_path will be its temporary location on the
        # local machine
        self.binary_path = None
        self.register_container("project", lambda: None, angr.Project | None, "The current angr project")
        self.register_container("simgrs", list, list[angr.SimulationManager], "Global simulation managers list")
        self.register_container("states", list, list[angr.SimState], "Global states list")
        self.register_container("patches", lambda: None, None, "Global patches update notifier")  # dummy
        self.register_container("cfg", lambda: None, angr.knowledge_plugins.cfg.CFGModel | None, "The current CFG")
        self.register_container("cfb", lambda: None, angr.analyses.cfg.CFBlanket | None, "The current CFBlanket")
        self.register_container("interactions", list, list[SavedInteraction], "Saved program interactions")
        # TODO: the current setup will erase all loaded protocols on a new project load! do we want that?
        self.register_container(
            "interaction_protocols",
            lambda: [PlainTextProtocol, BackslashTextProtocol],
            list[type[ProtocolInteractor]],
            "Available interaction protocols",
        )
        self.register_container("log", list, list[LogRecord], "Saved log messages", logging_permitted=False)
        self.register_container("current_trace", lambda: None, type[Trace], "Currently selected trace")
        self.register_container("traces", list, list[Trace], "Global traces list")

        self.register_container("active_view_state", lambda: None, "ViewState", "Currently focused view state")

        self.breakpoint_mgr = BreakpointManager()
        self.debugger_list_mgr = DebuggerListManager()
        self.debugger_mgr = DebuggerManager(self.debugger_list_mgr)

        self.project.am_subscribe(self.initialize)

        # Callbacks
        self._insn_backcolor_callback: Callable[[int, bool], None] | None = None  # (addr, is_selected)
        self._label_rename_callback: Callable[[int, str], None] | None = None  # (addr, new_name)
        self._set_comment_callback: Callable[[int, str], None] | None = None  # (addr, comment_text)
        self.handle_comment_changed_callback: Callable[[int, str, bool, bool, bool], None] | None = None

        # Setup logging
        initialize(self)

        self.cfg_args = None
        self.variable_recovery_args = None
        self._disassembly = {}
        self.pseudocode_variable_kb = None

        self.database_path = None

        # The image name when loading image
        self.img_name = None

        self._live = True

    #
    # Properties
    #

    @property
    def kb(self) -> angr.KnowledgeBase | None:
        if self.project.am_none:
            return None
        return self.project.kb

    def __getattr__(self, k):
        if k == "extra_containers":
            return {}

        try:
            return self.extra_containers[k]
        except KeyError:
            return super().__getattribute__(k)

    def __setattr__(self, k, v) -> None:
        if k in self.extra_containers:
            self.extra_containers[k].am_obj = v
        else:
            super().__setattr__(k, v)

    def __dir__(self):
        return list(super().__dir__()) + list(self.extra_containers)

    @property
    def insn_backcolor_callback(self):
        return self._insn_backcolor_callback

    @insn_backcolor_callback.setter
    def insn_backcolor_callback(self, v) -> None:
        self._insn_backcolor_callback = v

    @property
    def label_rename_callback(self):
        return self._label_rename_callback

    @label_rename_callback.setter
    def label_rename_callback(self, v) -> None:
        self._label_rename_callback = v

    @property
    def set_comment_callback(self) -> Callable[[int, str], None] | None:
        return self._set_comment_callback

    @set_comment_callback.setter
    def set_comment_callback(self, v) -> None:
        self._set_comment_callback = v

    #
    # Public methods
    #

    def register_container(self, name: str, default_val_func, ty, description: str, logging_permitted: bool = True):
        if name in self.extra_containers:
            cur_ty = self._container_defaults[name][1]
            if ty != cur_ty:
                raise ContainerAlreadyRegisteredError(
                    f"Container {name} already registered with different type: {ty} != {cur_ty}"
                )

        else:
            self._container_defaults[name] = (default_val_func, ty)
            self.extra_containers[name] = ObjectContainer(
                default_val_func(), description, logging_permitted=logging_permitted
            )

    def initialize(self, initialized: bool = False) -> None:
        if self.project.am_none:
            return

        self.patches.am_obj = self.kb.patches

        if not initialized and self.pseudocode_variable_kb is None:
            self.initialize_pseudocode_variable_kb()

    def initialize_pseudocode_variable_kb(self) -> None:
        self.pseudocode_variable_kb = KnowledgeBase(self.project.am_obj, name="pseudocode_variable_kb")

    def get_instruction_text_at(self, addr: int):
        """
        Get the text representation of an instruction at `addr`.

        :param int addr:    Address of the instruction.
        :return:            Text representation of the instruction, or None if no instruction can be found there.
        :rtype:             Optional[str]
        """

        if self.cfb is None:
            return None

        try:
            _, obj = self.cfb.floor_item(addr)
        except KeyError:
            # no object before addr exists
            return None

        if isinstance(obj, Block):
            if obj._using_pcode_engine:
                # TODO: Support getting disassembly from pypcode
                return "..."

            for insn in obj.capstone.insns:
                if insn.address == addr:
                    insn_piece = Instruction(insn, None, project=self.project)
                    return insn_piece.render()[0]
        return None

    def delete_hook(self, addr: int) -> None:
        self.project.unhook(addr)

    def add_breakpoint(self, obj: str | int, type_: str | None = None, size: int | None = None) -> None:
        """
        Convenience function to add a breakpoint.

        Examples:
        - `instance.add_breakpoint(0x1234)` sets an execution breakpoint on address 0x1234
        - `instance.add_breakpoint('main')` sets an execution breakpoint on `main` function
        - `instance.add_breakpoint('global_value')` sets a write breakpoint on `global_value`
        - `instance.add_breakpoint('global_value', 'read', 1)` sets a 1-byte read breakpoint on `global_value`
        """
        if isinstance(obj, int):
            addr = obj
        elif isinstance(obj, str):
            sym = self.project.loader.find_symbol(obj)
            if sym is None:
                _l.error("Couldn't resolve '%s'", obj)
                return
            addr = sym.rebased_addr
            if not size:
                size = sym.size
            if not type_:
                type_ = "execute" if sym.type == SymbolType.TYPE_FUNCTION else "write"
        elif type(obj) is Function:
            addr = obj.addr
            if not type_:
                type_ = "execute"
        else:
            _l.error("Unexpected target object type. Expected int | str | Function")
            return

        if not size:
            size = 1

        bp_type_map = {
            None: BreakpointType.Execute,
            "execute": BreakpointType.Execute,
            "write": BreakpointType.Write,
            "read": BreakpointType.Read,
        }
        if type_ not in bp_type_map:
            _l.error("Unknown breakpoint type '%s'. Expected %s", type_, " | ".join(bp_type_map.keys()))
            return

        bp = Breakpoint(bp_type_map[type_], addr, size)
        self.breakpoint_mgr.add_breakpoint(bp)

    def set_comment(self, addr: int, comment_text) -> None:
        kb = self.project.kb
        exists = addr in kb.comments

        # callback
        if comment_text is None and exists:
            if self.handle_comment_changed_callback is not None:
                self.handle_comment_changed_callback(addr, "", False, False, False)
            del kb.comments[addr]
        else:
            if self.handle_comment_changed_callback is not None:
                self.handle_comment_changed_callback(addr, comment_text, not exists, False, False)
            kb.comments[addr] = comment_text

        # TODO: can this be removed?
        if self.set_comment_callback is not None:
            self.set_comment_callback(addr, comment_text)  # pylint:disable=not-callable

    #
    # Private methods
    #

    def _reset_containers(self) -> None:
        for name, container in self.extra_containers.items():
            container.am_obj = self._container_defaults[name][0]()
            container.am_event()

        for dbg in list(self.debugger_list_mgr.debugger_list):
            self.debugger_list_mgr.remove_debugger(dbg)

        self.breakpoint_mgr.clear()
