from typing import TYPE_CHECKING, Optional
import logging

from PySide2.QtWidgets import QMessageBox

from angr import KnowledgeBase
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.atoms import Register, MemoryLocation, SpOffset
from angr.knowledge_plugins import Function
from angr.calling_conventions import DEFAULT_CC, SimCC, SimRegArg, SimStackArg

from .job import Job
from ...logic.threads import gui_thread_schedule_async

try:
    import argument_resolver
    from argument_resolver.slicer.slicer import cfg_slices_to_sinks, cfg_slice_to_sink
    from argument_resolver.transitive_closure import _transitive_closures, _vulnerable_atom
    from angr_patch.function_call_handler import Handler
except ImportError:
    argument_resolver = None

if TYPE_CHECKING:
    from ...plugins.dep_viewer import DependencyViewer
    from ..instance import Instance


l = logging.getLogger(name=__name__)


class DependencyAnalysisJob(Job):
    def __init__(self, func_addr=None, func_arg_idx=None):
        super().__init__("DependencyAnalysis")

        self.func_addr: Optional[int] = func_addr
        self.func_arg_idx: Optional[int] = func_arg_idx

    def _get_sink_and_atom(self, inst: 'Instance'):
        if self.func_addr is not None:
            sinks = [func for func in inst.kb.functions.values() if func.addr == self.func_addr]
            if not sinks:
                return None, None
            sink: Function = sinks[0]

            if sink.calling_convention is not None:
                cc: SimCC = sink.calling_convention
            else:
                cc: SimCC = DEFAULT_CC[inst.project.arch.name](inst.project.arch)

            # TODO: Handle stack-passing arguments
            # TODO: Handle variadic arguments
            arg = cc.arg_locs(None)[self.func_arg_idx]

            # convert arg into atom
            if isinstance(arg, SimRegArg):
                atom = Register(inst.project.arch.registers[arg.reg_name][0],
                                arg.size)
                return sink, atom
            else:
                raise NotImplementedError()

        return None, None

    def run(self, inst: 'Instance'):
        self._progress_callback(0.0)
        self._run(inst)
        self._progress_callback(100.0)

    def _run(self, inst: 'Instance'):
        if not argument_resolver:
            gui_thread_schedule_async(self._display_import_error)
            return

        self._progress_callback(10.0)
        sink, atom = self._get_sink_and_atom(inst)
        if sink is None:
            # invalid sink setup
            return None

        # make a copy of the kb
        kb_copy = self._get_new_kb_with_cfgs_and_functions(inst.project, inst.kb)

        self._progress_callback(20.0, text="Slicing CFG")
        slice = cfg_slice_to_sink(inst.cfg, sink)
        self._progress_callback(30.0, text="Calculating reaching definitions")
        rda = inst.project.analyses.ReachingDefinitions(
            subject=slice,
            observe_all=True,
            function_handler=Handler(inst.project),
            kb=kb_copy,
            dep_graph=DepGraph(),
        )
        self._progress_callback(80.0, text="Computing transitive closures")
        closures = _transitive_closures(atom, rda)

        # display in the dependencies view
        gui_thread_schedule_async(self._display_closures, (inst, closures, ))

        # visualize the CFG slice
        dep_plugin: Optional['DependencyViewer'] = inst.workspace.plugins.get_plugin_instance_by_name('DependencyViewer')
        if dep_plugin is None:
            l.warning("The DependencyViewer plugin is not activated.")
            return
        dep_plugin.covered_blocks.clear()
        for src, dsts in slice.transitions.items():
            if src not in dep_plugin.covered_blocks:
                block = inst.cfg.get_any_node(src)
                dep_plugin.covered_blocks[src] = block.size
            for dst in dsts:
                if dst not in dep_plugin.covered_blocks:
                    block = inst.cfg.get_any_node(dst)
                    dep_plugin.covered_blocks[dst] = block.size

    @staticmethod
    def _get_new_kb_with_cfgs_and_functions(project, kb):
        new_kb = KnowledgeBase(project)

        new_kb.cfgs = kb.cfgs.copy()
        new_kb.functions = kb.functions.copy()
        new_kb.labels = kb.labels.copy()
        new_kb.resolved_indirect_jumps = kb.resolved_indirect_jumps.copy()
        new_kb.unresolved_indirect_jumps = kb.unresolved_indirect_jumps.copy()

        return new_kb

    def _display_import_error(self):
        QMessageBox.critical(None,
                             "Import error",
                             "Failed to import argument_resolver package. Is operation-mango installed?",
                             )

    def _display_closures(self, inst, closures):
        view = inst.workspace.view_manager.first_view_in_category("dependencies")
        if view is None:
            return
        view.closures = closures
        try:
            view.reload()
        except Exception:
            l.warning("An error occurred when displaying the closures.", exc_info=True)
        inst.workspace.view_manager.raise_view(view)
