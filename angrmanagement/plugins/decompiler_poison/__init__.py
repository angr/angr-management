from collections import defaultdict

import ailment
from angr import AnalysesHub
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.optimization_passes import _all_optimization_passes
from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
from angr.knowledge_plugins import KnowledgeBasePlugin

from .. import BasePlugin

class PoisonPlugin(BasePlugin):
    def build_context_menu_node(self, node):
        if isinstance(node, CFunctionCall) and node.callee_func is not None:
            return [
                ('Poison call for this function', lambda: self.set_poison_local(node.codegen._func.addr, node.callee_func.addr)),
                ('Poison call globally', lambda: self.set_poison_global(node.callee_func.addr)),
            ]
        else:
            return []

    def set_poison_local(self, func, callee):
        self.workspace.instance.kb.get_plugin('decompiler_poison').local_poison[func].add(callee)

    def set_poison_global(self, callee):
        self.workspace.instance.kb.get_plugin('decompiler_poison').global_poison.add(callee)

class PoisonKnowledge(KnowledgeBasePlugin):
    def __init__(self, kb):
        self.kb = kb
        self.global_poison = set()
        self.local_poison = defaultdict(set)

    def is_poisoned(self, func, addr):
        return addr in self.global_poison or addr in self.local_poison[func]

    def copy(self):
        out = PoisonKnowledge(self.kb)
        out.global_poison = set(self.global_poison)
        out.local_poison = defaultdict(set, {key: set(val) for key, val in self.local_poison.items()})
        return out

class PoisonPass(OptimizationPass):
    """
    Allows the user to "poison" pieces of code, removing them and causing any conditional jumps pointing to that code
    to be removed and made unconditional in the opposite direction.
    """

    ARCHES = ["X86", "AMD64"]
    PLATFORMS = ["linux", "windows"]
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Poison Pass"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def is_poisoned(self, addr):
        return self.project.kb.get_plugin("decompiler_poison").is_poisoned(self._func.addr, addr)

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        poisoned = []

        for block in list(self._graph.nodes()):
            block: ailment.Block
            for stmt in block.statements:
                if isinstance(stmt, ailment.statement.Call) and self.is_poisoned(getattr(stmt.target, 'value', None)):
                    poisoned.append(block)
                    break

        while poisoned:
            block = poisoned.pop()
            preds = list(self._graph.predecessors(block))
            for pred in preds:
                pred: ailment.Block
                if len(list(self._graph.successors(pred))) == 1:
                    poisoned.append(pred)
                else:
                    for i, stmt in enumerate(pred.statements):
                        if isinstance(stmt, ailment.statement.ConditionalJump):
                            pred.statements.pop(i)
                            break
                    #else:
                    #    raise Exception("uh oh")

            self._remove_block(block)

PoisonKnowledge.register_default('decompiler_poison', PoisonKnowledge)
_all_optimization_passes.append((PoisonPass, True))
AnalysesHub.register_default('PoisonPass', PoisonPass)
