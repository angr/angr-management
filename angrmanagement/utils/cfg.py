from __future__ import annotations

import logging
from collections import defaultdict

from angr.ailment.expression import Const
from angr.ailment.statement import ConditionalJump, Jump
from angr.analyses.decompiler.clinic import Clinic

from .edge import EdgeSort

log = logging.getLogger("utils.cfg")


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
