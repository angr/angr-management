from typing import TYPE_CHECKING, Optional
import logging

from angr import KnowledgeBase

from .job import Job

try:
    import argument_resolver
    from argument_resolver.slicer.slicer import cfg_slices_to_sinks, cfg_slice_to_sink
except ImportError:
    argument_resolver = None

if TYPE_CHECKING:
    from ...plugins.dep_viewer import DependencyViewer
    from ..instance import Instance


l = logging.getLogger(name=__name__)


class DependencyAnalysisJob(Job):
    def __init__(self):
        super().__init__("DependencyAnalysis")

    def run(self, inst: 'Instance'):
        if not argument_resolver:
            # TODO: Raise a warning
            return

        sinks = [ func for func in inst.kb.functions.values() if func.name == "system" ]
        sink = sinks[0]

        # make a copy of the kb
        kb_copy = self._get_new_kb_with_cfgs_and_functions(inst.project, inst.kb)

        slice = cfg_slice_to_sink(inst.cfg, sink)

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

