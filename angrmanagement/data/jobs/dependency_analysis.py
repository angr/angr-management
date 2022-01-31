from functools import partial
from typing import TYPE_CHECKING, Optional, Generator, List, Tuple, Set
import logging

from PySide2.QtWidgets import QMessageBox

from angr import KnowledgeBase
from angr.analyses.reaching_definitions.external_codeloc import ExternalCodeLocation
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.analyses.reaching_definitions.call_trace import CallTrace
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE
from angr.knowledge_plugins.key_definitions.atoms import Register, MemoryLocation, SpOffset
from angr.knowledge_plugins import Function
from angr.calling_conventions import DEFAULT_CC, SimCC, SimRegArg, SimStackArg
from angr.sim_type import SimType

from .job import Job
from ...logic.threads import gui_thread_schedule_async

try:
    import argument_resolver
    from argument_resolver.handlers import handler_factory, StdioHandlers, StdlibHandlers, StringHandlers
    from argument_resolver.transitive_closure import transitive_closures_from_defs
    from argument_resolver.call_trace_visitor import CallTraceSubject
except ImportError:
    argument_resolver = None

if TYPE_CHECKING:
    from angr.knowledge_plugins.key_definitions.definition import Definition
    from angr.knowledge_plugins.key_definitions.atoms import Atom
    from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
    from ...plugins.dep_viewer import DependencyViewer
    from ..instance import Instance


l = logging.getLogger(name=__name__)


class DependencyAnalysisJob(Job):
    """
    Implements a job for dependency analysis.
    """

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
            arg_locs = cc.arg_locs(sink.prototype)
            arg = arg_locs[self.func_arg_idx]

            # convert arg into atom
            if isinstance(arg, SimRegArg):
                atom = Register(inst.project.arch.registers[arg.reg_name][0],
                                arg.size)
                return sink, atom
            else:
                raise NotImplementedError()

        return None, None

    def _run(self, inst: 'Instance'):
        self._progress_callback(0.0)
        self._perform(inst)
        self._progress_callback(100.0)

    def _perform(self, inst: 'Instance'):
        if not argument_resolver:
            gui_thread_schedule_async(self._display_import_error)
            return

        self._progress_callback(10.0, text="Extracting sink and atom")
        sink, atom = self._get_sink_and_atom(inst)
        if sink is None:
            # invalid sink setup
            return None

        closures = { }
        excluded_functions: Set[int] = set()
        min_depth = 1
        max_depth = 8
        progress_chunk = 70.0 / (max_depth - min_depth)

        for depth in range(min_depth, max_depth):
            base_progress: float = 30.0 + (depth - min_depth) * progress_chunk
            self._progress_callback(base_progress,
                                    text="Calculating reaching definitions... depth %d." % depth)
            # generate RDA observation points
            observation_points = set()
            for pred in inst.cfg.am_obj.get_predecessors(inst.cfg.am_obj.get_any_node(self.func_addr)):
                if pred.instruction_addrs:
                    call_inst_addr = pred.instruction_addrs[-1]
                    observation_point = ('insn', call_inst_addr, OP_BEFORE)
                    observation_points.add(observation_point)

            for idx, total, dep in self._dependencies(sink, [(atom,SimType())], inst.project.kb, inst.project, depth,
                                                      excluded_functions, observation_points):
                self._progress_callback(
                    base_progress + idx / total * progress_chunk,
                    text="Computing transitive closures: %d/%d - depth %d" % (idx + 1, total, depth))

                all_defs = set()
                # find the instructions that call this function
                for pred in inst.cfg.am_obj.get_predecessors(inst.cfg.am_obj.get_any_node(self.func_addr)):
                    if pred.instruction_addrs:
                        call_inst_addr = pred.instruction_addrs[-1]
                        loc = ('insn', call_inst_addr, OP_BEFORE)
                        if loc in dep.observed_results:
                            observed_result = dep.observed_results[loc]
                            defs_ = observed_result.get_definitions_from_atoms([atom])
                            all_defs |= defs_

                try:
                    cc = transitive_closures_from_defs(all_defs, dep)
                except Exception:  # pylint:disable=broad-except
                    l.warning("Exception occurred when computing transitive clousure. Skip.")
                    continue

                # determine if there is any values are marked as coming from External. these values are not resolved
                # within the current call-depth range
                has_external = False
                for def_, graph in closures.items():
                    for node in graph.nodes():
                        if isinstance(node.codeloc, ExternalCodeLocation):
                            # yes!
                            has_external = True
                            break
                    if has_external:
                        break
                if not has_external:
                    # fully resolved - we should exclude this function for future exploration
                    current_function_address = dep.subject.content.current_function_address()
                    l.info("Exclude function %#x from future slices since the data dependencies are fully resolved.",
                           current_function_address)
                    excluded_functions.add(current_function_address)

                closures.update(cc)

        # display in the dependencies view
        gui_thread_schedule_async(self._display_closures, (inst, atom, sink.addr, closures, ))

        return

    @staticmethod
    def _dependencies(subject, sink_atoms: List[Tuple['Atom',SimType]], kb, project, max_depth: int,
                      excluded_funtions: Set[int],
                      observation_points: Set[Tuple]) -> Generator[Tuple[int,int,'ReachingDefinitionsAnalysis'], None, None]:
        Handler = handler_factory([
            StdioHandlers,
            StdlibHandlers,
            StringHandlers,
        ])

        if isinstance(subject, Function):
            sink = subject
        else:
            raise TypeError('Unsupported type of subject %s.' % type(subject))

        # peek into the callgraph and discover all functions reaching the sink within N layers of calls, which is determined
        # by the depth parameter
        queue: List[Tuple[CallTrace, int]] = [(CallTrace(sink.addr), 0)]
        starts: Set[CallTrace] = set()
        encountered: Set[int] = set(excluded_funtions)
        while queue:
            trace, curr_depth = queue.pop(0)
            if trace.current_function_address() in starts:
                continue
            caller_func_addr = trace.current_function_address()
            callers: Set[int] = set(kb.functions.callgraph.predecessors(caller_func_addr))
            # remove the functions that we already came across - essentially bypassing recursive function calls
            callers = set(addr for addr in callers if addr not in encountered)
            caller_depth = curr_depth + 1
            if caller_depth >= max_depth:
                # reached the depth limit. add them to potential analysis starts
                starts |= set(map(lambda caller_addr: trace.step_back(caller_addr, None, caller_func_addr), callers))
            else:
                # add them to the queue
                for item in map(lambda caller_addr: (trace.step_back(caller_addr, None, caller_func_addr),
                                                     caller_depth),
                                callers
                                ):
                    queue.append(item)
            encountered |= callers

        l.info("Discovered %d function starts at call-depth %d for sink %r.",
               len(starts),
               max_depth,
               sink
               )

        for idx, start in enumerate(starts):
            handler = Handler(project, False, sink_function=sink, sink_atoms=sink_atoms)
            try:
                rda = project.analyses.ReachingDefinitions(
                    subject=CallTraceSubject(start, kb.functions[start.current_function_address()]),
                    observe_all=False,
                    observation_points=observation_points,
                    function_handler=handler,
                    kb=kb,
                    dep_graph=DepGraph()
                )
            except Exception:  # pylint:disable=broad-except
                l.warning("Failed to compute dependencies for function %s.", start, exc_info=True)
                continue
            yield idx, len(starts), rda

    @staticmethod
    def _get_new_kb_with_cfgs_and_functions(project, kb):
        new_kb = KnowledgeBase(project)

        new_kb.cfgs = kb.cfgs.copy()
        new_kb.functions = kb.functions.copy()
        new_kb.labels = kb.labels.copy()
        new_kb.resolved_indirect_jumps = kb.resolved_indirect_jumps.copy()
        new_kb.unresolved_indirect_jumps = kb.unresolved_indirect_jumps.copy()

        return new_kb

    @staticmethod
    def _display_import_error():
        QMessageBox.critical(None,
                             "Import error",
                             "Failed to import argument_resolver package. Is operation-mango installed?",
                             )

    @staticmethod
    def _display_closures(inst, sink_atom: 'Atom', sink_addr: int, closures):
        view = inst.workspace.view_manager.first_view_in_category("dependencies")
        if view is None:
            return

        view.sink_atom = sink_atom
        view.sink_ins_addr = sink_addr
        view.closures = closures
        try:
            view.reload()
        except Exception:
            l.warning("An error occurred when displaying the closures.", exc_info=True)
        inst.workspace.view_manager.raise_view(view)
