from __future__ import annotations

import logging
from collections import defaultdict

from ailment.expression import Const
from ailment.statement import ConditionalJump, Jump
from angr.analyses.decompiler.clinic import Clinic

from .edge import EdgeSort

log = logging.getLogger("utils.cfg")


def _get_branch_instr(disassembly, node):
    if len(node.out_branches) > 1:
        log.warning(
            "_get_branch_instr(): %s has more than one out_branches. Only the first one is considered for now. "
            "Report it to GitHub and it will be fixed.",
            node,
        )
    if not node.out_branches:
        # huh, why is it empty?
        log.error("_get_branch_instr(): %s does not have any out branches. Please report to GitHub.", node)
        return None

    # Get the instruction address that contains the jump
    ins_addr = next(iter(node.out_branches.keys()))

    # Get the Instruction
    try:
        instr = disassembly["instructions"][ins_addr]
    except KeyError:
        # the instruction is not found
        log.error("_get_branch_instr(): Branch instruction %#x is not found in the Disassembly instance.", ins_addr)
        return None

    return instr


def categorize_edges(disassembly, edges) -> None:
    """
    Categorize each edge.

    :param disassembly: A Disassembly analysis instance.
    :param list edges:  A list of edges.
    :return:            None
    """

    edges_by_node = defaultdict(list)

    for edge in edges:
        if edge.sort != EdgeSort.EXCEPTION_EDGE:
            edges_by_node[edge.src].append(edge)

    for src_node, items in edges_by_node.items():
        if len(items) == 1:
            # is it a back edge?
            # TODO: an accurate back edge identification requires us to identify loop heads. although we do identify
            # TODO: loop nodes at some point, the information is not available here...
            edge = items[0]
            if edge.src.addr >= edge.dst.addr:
                edge.sort = EdgeSort.BACK_EDGE

        elif len(items) == 2:
            # actually, let's determine which branch is the false branch
            edge_a, edge_b = items

            if isinstance(disassembly, Clinic):
                last_stmt = edge_a.src.statements[-1] if edge_a.src.statements else None
                fallthrough = None
                if isinstance(last_stmt, ConditionalJump):
                    fallthrough = last_stmt.false_target.value
                elif isinstance(last_stmt, Jump):
                    # this is unexpected since this block has two successors somehow, but the last statement is a Jump
                    # anyway we pick the current value as the fallthrough value
                    if isinstance(last_stmt.target, Const):
                        fallthrough = last_stmt.target.value
                else:
                    # a block whose last statement is not a jump or a conditional jump but has two successors?
                    fallthrough = None
            else:
                fallthrough = src_node.addr + src_node.size

            if edge_a.dst.addr == fallthrough and edge_b.dst.addr != fallthrough:
                edge_a.sort = EdgeSort.FALSE_BRANCH
                edge_b.sort = EdgeSort.TRUE_BRANCH
            elif edge_a.dst.addr != fallthrough and edge_b.dst.addr == fallthrough:
                edge_a.sort = EdgeSort.TRUE_BRANCH
                edge_b.sort = EdgeSort.FALSE_BRANCH
            else:
                # huh, there are either two fall-throughs or no fall-throughs
                pass
