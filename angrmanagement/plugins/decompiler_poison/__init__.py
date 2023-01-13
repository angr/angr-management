from collections import defaultdict

import ailment
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
from angr.knowledge_plugins import KnowledgeBasePlugin

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.views import CodeView


class PoisonKnowledge(KnowledgeBasePlugin):
    """
    See PoisonPlugin. This is the storage mechanism in the knowledgebase.
    """

    def __init__(self, kb):
        self.kb = kb
        self.global_poison = set()
        self.local_poison = defaultdict(set)

    def is_poisoned_local(self, func, addr):
        return addr in self.local_poison[func]

    def is_poisoned_global(self, addr):
        return addr in self.global_poison

    def is_poisoned(self, func, addr):
        return self.is_poisoned_local(func, addr) or self.is_poisoned_global(addr)

    def copy(self):
        out = PoisonKnowledge(self.kb)
        out.global_poison = set(self.global_poison)
        out.local_poison = defaultdict(set, {key: set(val) for key, val in self.local_poison.items()})
        return out


class PoisonPass(OptimizationPass):
    """
    See PoisonPlugin. This is the optimization pass that trims poisoned branches.
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
        return self.project.kb.decompiler_poison.is_poisoned(self._func.addr, addr)

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        poisoned = []

        for block in list(self._graph.nodes()):
            block: ailment.Block
            for stmt in block.statements:
                if isinstance(stmt, ailment.statement.Call) and self.is_poisoned(getattr(stmt.target, "value", None)):
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
                    # else:
                    #    raise Exception("uh oh")

            self._remove_block(block)


class PoisonPlugin(BasePlugin):
    """
    Allows the user to "poison" pieces of code, removing them and causing any conditional jumps pointing to that code
    to be removed and made unconditional in the opposite direction.
    """

    OPTIMIZATION_PASSES = [(PoisonPass, True)]

    def build_context_menu_node(self, node):
        if isinstance(node, CFunctionCall) and node.callee_func is not None:
            yield None
            if self.knowledge.is_poisoned_local(node.codegen._func.addr, node.callee_func.addr):
                yield "Remove poison for this function", lambda: self.set_poison_local(
                    node.codegen._func.addr, node.callee_func.addr, False
                )
            else:
                yield "Poison call for this function", lambda: self.set_poison_local(
                    node.codegen._func.addr, node.callee_func.addr, True
                )
            if self.knowledge.is_poisoned_global(node.callee_func.addr):
                yield "Remove global poison", lambda: self.set_poison_global(node.callee_func.addr, False)
            else:
                yield "Poison call globally", lambda: self.set_poison_global(node.callee_func.addr, True)
        else:
            pass

    @property
    def knowledge(self) -> "PoisonKnowledge":
        return self.workspace.main_instance.kb.decompiler_poison

    def set_poison_local(self, func, callee, value):
        if value:
            self.knowledge.local_poison[func].add(callee)
        else:
            self.knowledge.local_poison[func].discard(callee)
        if isinstance(self.workspace.view_manager.current_tab, CodeView):
            self.workspace.view_manager.current_tab.decompile()

    def set_poison_global(self, callee, value):
        if value:
            self.knowledge.global_poison.add(callee)
        else:
            self.knowledge.global_poison.discard(callee)
        if isinstance(self.workspace.view_manager.current_tab, CodeView):
            self.workspace.view_manager.current_tab.decompile()

    @staticmethod
    def _poison_to_string(a_set):
        return ",".join(hex(a) for a in a_set)

    @staticmethod
    def _string_to_poison(a_string):
        return {int(a, 16) for a in a_string.split(",")}

    def angrdb_store_entries(self):
        poison = self.workspace.main_instance.kb.decompiler_poison.global_poison
        if poison:
            yield ("global_poison", self._poison_to_string(poison))
        for func, poison in self.workspace.main_instance.kb.decompiler_poison.local_poison.items():
            if poison:
                yield ("local_poison_" + hex(func), self._poison_to_string(poison))

    def angrdb_load_entry(self, key: str, value: str):
        if key == "global_poison":
            self.workspace.main_instance.kb.decompiler_poison.global_poison = self._string_to_poison(value)
        elif key.startswith("local_poison_"):
            func = int(key.split("_")[2], 16)
            self.workspace.main_instance.kb.decompiler_poison.local_poison[func] = self._string_to_poison(value)


PoisonKnowledge.register_default("decompiler_poison", PoisonKnowledge)
