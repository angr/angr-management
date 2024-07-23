from __future__ import annotations

import itertools
import re
from typing import TYPE_CHECKING

import networkx as nx
from angr.analyses.disassembly import ConstantOperand, Disassembly, Instruction, MemoryOperand
from angr.errors import SimEngineError

from angrmanagement.utils import string_at_addr

if TYPE_CHECKING:
    from angr.block import CapstoneInsn
    from angr.knowledge_plugins.functions.function import Function

    from angrmanagement.ui.views import DisassemblyView


class FunctionDiff:
    """
    A class to represent a diff of two functions, which may either be part of a larger disassembly view or not.
    Diffs are recorded in the rev_{change,add,del} sets, which are instruction addresses.

    """

    OBJ_DELETED = "del"
    OBJ_ADDED = "add"
    OBJ_CHANGED = "chg"
    OBJ_UNMODIFIED = "nop"

    # pylint:disable=unused-argument
    def __init__(
        self,
        func_base: Function,
        func_rev: Function,
        disas_base: Disassembly = None,
        disas_rev: Disassembly = None,
        prefer_symbols: bool = True,
        resolve_strings: bool = True,
        resolve_insn_addrs: bool = True,
        **kwargs,
    ) -> None:
        self.func_base = func_base
        self.func_rev = func_rev
        self.disas_base = disas_base
        self.disas_rev = disas_rev

        self.rev_change_set = set()
        self.rev_add_set = set()
        self.rev_del_set = set()

        self._prefer_symbols = prefer_symbols
        self._resolve_strings = resolve_strings
        self._resolve_insn_addrs = resolve_insn_addrs
        self._insn_mnem_check = 3

    @property
    def differs(self):
        return bool(self.rev_change_set or self.rev_add_set or self.rev_del_set)

    @property
    def prefer_symbols(self):
        return self._prefer_symbols and self.disas_base is not None and self.disas_rev is not None

    @staticmethod
    def is_executable_address(address, proj):
        for section in proj.loader.main_object.sections:
            if section.is_executable and section.min_addr <= address <= section.max_addr:
                return True

        return False

    def _linear_asm_from_function(
        self, func: Function, disas: Disassembly = None, as_dict: bool = False
    ) -> list[CapstoneInsn]:
        sorted_blocks = sorted(func.blocks, key=lambda b: b.addr)
        instruction_lists = [block.disassembly.insns for block in sorted_blocks]
        instructions = list(itertools.chain.from_iterable(instruction_lists))
        if not self.prefer_symbols:
            return instructions if not as_dict else {i.address: i for i in instructions}

        symbolized_instructions = [disas.raw_result_map["instructions"][insn.address] for insn in instructions]

        return symbolized_instructions if not as_dict else {i.addr: i for i in symbolized_instructions}

    def diff_insn(self, base_insn: CapstoneInsn | Instruction, rev_insn: CapstoneInsn | Instruction):
        if self._prefer_symbols:
            if base_insn.render() == rev_insn.render():
                return FunctionDiff.OBJ_UNMODIFIED

            if base_insn.mnemonic.render() == rev_insn.mnemonic.render() and len(base_insn.operands) == len(
                rev_insn.operands
            ):
                if not self._resolve_strings and not self._resolve_insn_addrs:
                    return FunctionDiff.OBJ_CHANGED

                # attempt to resolve strings that act as symbols
                base_mem_ops = [op for op in base_insn.operands if isinstance(op, MemoryOperand | ConstantOperand)]
                if base_mem_ops:
                    rev_mem_ops = [op for op in rev_insn.operands if isinstance(op, MemoryOperand | ConstantOperand)]
                    if len(rev_mem_ops) == len(base_mem_ops) == 1:
                        base_mem_op = base_mem_ops[0]
                        rev_mem_op = rev_mem_ops[0]

                        try:
                            if isinstance(base_mem_op, MemoryOperand):
                                base_mem_op_addr = list(base_mem_op.values)[0].val
                            else:
                                base_mem_op_addr = base_mem_op.children[0].val
                        except (IndexError, KeyError, ValueError, AttributeError):
                            return FunctionDiff.OBJ_CHANGED

                        try:
                            if isinstance(rev_mem_op, MemoryOperand):
                                rev_mem_op_addr = list(rev_mem_op.values)[0].val
                            else:
                                rev_mem_op_addr = rev_mem_op.children[0].val
                        except (IndexError, KeyError, ValueError, AttributeError):
                            return FunctionDiff.OBJ_CHANGED

                        base_str = string_at_addr(
                            self.func_base.project.kb.cfgs.get_most_accurate(), base_mem_op_addr, self.func_base.project
                        )
                        rev_str = string_at_addr(
                            self.func_rev.project.kb.cfgs.get_most_accurate(), rev_mem_op_addr, self.func_rev.project
                        )

                        if base_str is not None and base_str == rev_str:
                            base_insn_str = re.sub(r"\[.*\]", base_str, base_insn.render()[0])
                            rev_insn_str = re.sub(r"\[.*\]", base_str, rev_insn.render()[0])

                            if base_insn_str == rev_insn_str:
                                return FunctionDiff.OBJ_UNMODIFIED
                        elif self._resolve_insn_addrs and (
                            self.is_executable_address(base_mem_op_addr, self.func_base.project)
                            and self.is_executable_address(rev_mem_op_addr, self.func_rev.project)
                        ):
                            try:
                                base_blk = self.func_base.get_block(base_mem_op_addr)
                            except SimEngineError:
                                return FunctionDiff.OBJ_CHANGED

                            try:
                                rev_blk = self.func_rev.get_block(rev_mem_op_addr)
                            except SimEngineError:
                                return FunctionDiff.OBJ_CHANGED

                            base_mnem = [ins.mnemonic for ins in base_blk.disassembly.insns][: self._insn_mnem_check]
                            rev_mnem = [ins.mnemonic for ins in rev_blk.disassembly.insns][: self._insn_mnem_check]
                            if base_mnem == rev_mnem:
                                return FunctionDiff.OBJ_UNMODIFIED

                return FunctionDiff.OBJ_CHANGED

            return FunctionDiff.OBJ_ADDED
        else:
            if base_insn.mnemonic != rev_insn.mnemonic or len(base_insn.operands) != len(rev_insn.operands):
                return FunctionDiff.OBJ_ADDED

            if base_insn.op_str != rev_insn.op_str:
                return FunctionDiff.OBJ_CHANGED

            return FunctionDiff.OBJ_UNMODIFIED

    def addr_diff_value(self, addr: int):
        if addr in self.rev_del_set:
            return self.OBJ_DELETED
        elif addr in self.rev_add_set:
            return self.OBJ_ADDED
        elif addr in self.rev_change_set:
            return self.OBJ_CHANGED
        else:
            return self.OBJ_UNMODIFIED

    def compute_function_diff(self) -> None:
        pass


class LinearFunctionDiff(FunctionDiff):
    """
    A function diff calculated by traversing two disassemblies linearly and checking index by index.
    """

    def __init__(
        self,
        func_base: Function,
        func_rev: Function,
        disas_base: Disassembly = None,
        disas_rev: Disassembly = None,
        prefer_symbols: bool = True,
        resolve_strings: bool = True,
        **kwargs,
    ) -> None:
        super().__init__(
            func_base,
            func_rev,
            prefer_symbols=prefer_symbols,
            resolve_strings=resolve_strings,
            disas_base=disas_base,
            disas_rev=disas_rev,
            **kwargs,
        )
        self.base_insns = self._linear_asm_from_function(func_base, disas=self.disas_base)
        self.rev_insns = self._linear_asm_from_function(func_rev, disas=self.disas_rev)
        self.compute_function_diff()

    def compute_function_diff(self) -> None:
        for idx, base_insn in enumerate(self.base_insns):
            if idx >= len(self.rev_insns):
                break

            rev_insn = self.rev_insns[idx]
            rev_addr = rev_insn.addr if self.prefer_symbols else rev_insn.address
            if self.diff_insn(base_insn, rev_insn) in (self.OBJ_CHANGED, self.OBJ_ADDED):
                self.rev_change_set.add(rev_addr)
                continue

        if len(self.rev_insns) <= len(self.base_insns) or not self.base_insns:
            return

        # if we end up here, then we have more rev_insns to parse
        # pylint:disable=undefined-loop-variable
        for rev_insn in self.rev_insns[idx:]:
            rev_addr = rev_insn.addr if self.prefer_symbols else rev_insn.address
            self.rev_add_set.add(rev_addr)


class BFSFunctionDiff(FunctionDiff):
    """
    Use two graphs to compute a function diff, performing Linear diff on each block for each position.
    The traversal of both graphs are done in a BFS manner.
    """

    def __init__(
        self,
        func_base: Function,
        func_rev: Function,
        view_base: DisassemblyView = None,
        view_rev: DisassemblyView = None,
        **kwargs,
    ) -> None:
        super().__init__(func_base, func_rev, **kwargs)
        self.base_cfg = view_base._flow_graph.function_graph.supergraph
        self.rev_cfg = view_rev._flow_graph.function_graph.supergraph
        self.base_insns = self._linear_asm_from_function(func_base, disas=self.disas_base, as_dict=True)
        self.rev_insns = self._linear_asm_from_function(func_rev, disas=self.disas_rev, as_dict=True)
        self.compute_function_diff()

    @staticmethod
    def supergraph_block_to_insns(function, super_block):
        instructions = []
        for cnode in super_block.cfg_nodes:
            ins_blk = function.get_block(cnode.addr)
            instructions += list(ins_blk.disassembly.insns)

        return instructions

    @staticmethod
    def bfs_list_block_levels(graph: nx.DiGraph):
        block_levels = []
        start_block = [n for n in graph.nodes if graph.in_degree(n) == 0][0]
        bfs = list(nx.bfs_successors(graph, start_block))
        for blk_tree in bfs:
            source, children = blk_tree

            if len(children) == 1:
                block_levels.append(children)
            elif len(children) == 2:
                fallthrough = source.addr + source.size
                if children[0].addr == fallthrough:
                    first, second = children[:]
                else:
                    first, second = children[::-1]

                block_levels.append([first, second])

        block_levels = [[start_block]] + block_levels
        return block_levels

    def compute_function_diff(self) -> None:
        base_levels = self.bfs_list_block_levels(self.base_cfg)
        rev_levels = self.bfs_list_block_levels(self.rev_cfg)
        diff_map = {}

        for level_idx, base_level in enumerate(base_levels):
            if level_idx >= len(rev_levels):
                break

            rev_blocks = rev_levels[level_idx]
            for block_idx, base_block in enumerate(base_level):
                if block_idx >= len(rev_blocks):
                    break

                unmodified_insns = []
                rev_insns = self.supergraph_block_to_insns(self.func_rev, rev_blocks[block_idx])

                # find unmodified instructions
                for base_insn in self.supergraph_block_to_insns(self.func_base, base_block):
                    # we are now in a single block starting with the base instruction;
                    # what we want to do now is first find all the original instructions in the
                    # new block and mark those as nops
                    for rev_insn in rev_insns:
                        if rev_insn.address in diff_map:
                            continue

                        if (
                            self.diff_insn(self.base_insns[base_insn.address], self.rev_insns[rev_insn.address])
                            == self.OBJ_UNMODIFIED
                        ):
                            diff_map[rev_insn.address] = self.OBJ_UNMODIFIED
                            unmodified_insns.append(rev_insn.address)
                            break

                # find changed instructions
                first_unmodified_address = unmodified_insns[0] if unmodified_insns else None
                for insn_idx, _base_insn in enumerate(self.supergraph_block_to_insns(self.func_base, base_block)):
                    if insn_idx >= len(rev_insns):
                        break

                    rev_insn = rev_insns[insn_idx]
                    if first_unmodified_address is not None and rev_insn.address < first_unmodified_address:
                        diff_map[rev_insn.address] = self.OBJ_ADDED
                        continue

                    if rev_insn.address in diff_map:
                        continue

                    diff_map[rev_insn.address] = self.OBJ_CHANGED

        for rev_level in rev_levels:
            for rev_block in rev_level:
                for rev_insn in self.supergraph_block_to_insns(self.func_rev, rev_block):
                    if rev_insn.address not in diff_map:
                        diff_map[rev_insn.address] = self.OBJ_ADDED

        # add to colors
        for addr, diff_val in diff_map.items():
            if diff_val == self.OBJ_CHANGED:
                self.rev_change_set.add(addr)
            elif diff_val == self.OBJ_ADDED:
                self.rev_add_set.add(addr)
