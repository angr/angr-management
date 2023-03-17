import itertools
from typing import List

import networkx as nx
from angr.knowledge_plugins.functions.function import Function
from angr.block import CapstoneInsn
from angr.codenode import BlockNode


class FunctionDiff:
    OBJ_DELETED = "del"
    OBJ_ADDED = "add"
    OBJ_CHANGED = "chg"
    OBJ_UNMODIFIED = "nop"

    def __init__(self, func_base: Function, func_rev: Function):
        self.func_base = func_base
        self.func_rev = func_rev

        self.rev_change_set = set()
        self.rev_add_set = set()
        self.rev_del_set = set()

        self.compute_function_diff()

    def addr_diff_value(self, addr):
        if addr in self.rev_del_set:
            return self.OBJ_DELETED
        elif addr in self.rev_add_set:
            return self.OBJ_ADDED
        elif addr in self.rev_change_set:
            return self.OBJ_CHANGED
        else:
            return self.OBJ_UNMODIFIED

    def compute_function_diff(self):
        pass


class LinearFunctionDiff(FunctionDiff):
    def __init__(self, func_base: Function, func_rev: Function):
        self.base_insns = self._linear_asm_from_function(func_base)
        self.rev_insns = self._linear_asm_from_function(func_rev)
        super().__init__(func_base, func_rev)

    @staticmethod
    def _linear_asm_from_function(func: Function) -> List[CapstoneInsn]:
        sorted_blocks = sorted(list(func.blocks), key=lambda b: b.addr)
        instruction_lists = [block.disassembly.insns for block in sorted_blocks]
        return list(itertools.chain.from_iterable(instruction_lists))
    
    @staticmethod
    def diff_insn(base_insn, rev_insn):
        if base_insn.mnemonic != rev_insn.mnemonic or len(base_insn.operands) != len(rev_insn.operands):
            return FunctionDiff.OBJ_ADDED

        base_args = base_insn.op_str.split(", ")
        rev_args = rev_insn.op_str.split(", ")
        if base_args != rev_args:
            return FunctionDiff.OBJ_CHANGED
        
        return FunctionDiff.OBJ_UNMODIFIED

    def compute_function_diff(self):
        for idx, base_insn in enumerate(self.base_insns):
            if idx >= len(self.rev_insns):
                break

            rev_insn = self.rev_insns[idx]
            if self.diff_insn(base_insn, rev_insn) in (self.OBJ_CHANGED, self.OBJ_ADDED):
                self.rev_change_set.add(rev_insn.address)
                continue

        if len(self.rev_insns) <= len(self.base_insns) or not self.base_insns:
            return

        # if we end up here, then we have more rev_insns to parse
        for rev_insn in self.rev_insns[idx:]:
            self.rev_add_set.add(rev_insn.address)


class BFSFunctionDiff(FunctionDiff):
    def __init__(self, func_base: Function, func_rev: Function):
        self.base_cfg = func_base.graph
        self.rev_cfg = func_rev.graph
        super().__init__(func_base, func_rev)

    @staticmethod
    def bfs_list_block_levels(function: Function, graph: nx.DiGraph):
        block_levels = []
        bfs = list(nx.bfs_successors(graph, function.startpoint))
        for blk_tree in bfs:
            source, children = blk_tree
            source = function.get_block(source.addr)
            children = [function.get_block(c.addr) for c in children]

            if len(children) == 1:
                block_levels.append(children)
            elif len(children) == 2:
                fallthrough = source.addr + source.size
                if children[0].addr == fallthrough:
                    first, second = children[:]
                else:
                    first, second = children[::-1]
                    
                block_levels.append([first, second])

        block_levels = [[function.get_block(function.startpoint.addr)]] + block_levels
        return block_levels

    def compute_function_diff(self):
        base_levels = self.bfs_list_block_levels(self.func_base, self.base_cfg)
        rev_levels = self.bfs_list_block_levels(self.func_rev, self.rev_cfg)
        diff_map = {}

        for level_idx, base_level in enumerate(base_levels):
            if level_idx >= len(rev_levels):
                break
            
            rev_blocks = rev_levels[level_idx] 
            for block_idx, base_block in enumerate(base_level):
                if block_idx >= len(rev_blocks):
                    break

                unmodified_insns = list()
                rev_insns = rev_blocks[block_idx].disassembly.insns

                # find unmodified instructions
                for base_insn in base_block.disassembly.insns:
                    # we are now in a single block starting with the base instruction;
                    # what we want to do now is first find all the original instructions in the
                    # new block and mark those as nops
                    for rev_insn in rev_insns:
                        if LinearFunctionDiff.diff_insn(base_insn, rev_insn) == self.OBJ_UNMODIFIED:
                            diff_map[rev_insn.address] = self.OBJ_UNMODIFIED
                            unmodified_insns.append(rev_insn.address)
                            break

                # find changed instructions
                first_unmodified_address = unmodified_insns[0] if unmodified_insns else None
                for insn_idx, base_insn in enumerate(base_block.disassembly.insns):
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
                for rev_insn in rev_block.disassembly.insns:
                    if rev_insn.address not in diff_map:
                        diff_map[rev_insn.address] = self.OBJ_ADDED

        # add to colors
        for addr, diff_val in diff_map.items():
            if diff_val == self.OBJ_CHANGED:
                self.rev_change_set.add(addr)
            elif diff_val == self.OBJ_ADDED:
                self.rev_add_set.add(addr)