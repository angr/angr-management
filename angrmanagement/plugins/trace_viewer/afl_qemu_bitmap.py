import logging
import math

import networkx as nx
from angr.knowledge_plugins.functions import Function
from PySide6.QtGui import QColor

_l = logging.getLogger(name=__name__)


class AFLQemuBitmap:
    HIT_COLOR = QColor(0xEE, 0xFF, 0xEE)
    MISS_COLOR = QColor(0x99, 0x00, 0x00, 0x30)
    FUNCTION_NOT_VISITED_COLOR = QColor(0x99, 0x00, 0x00, 0x20)
    BUCKET_COLORS = [
        QColor(0xEF, 0x65, 0x48, 0x20),
        QColor(0xFC, 0x8D, 0x59, 0x60),
        QColor(0xFD, 0xBB, 0x84, 0x60),
        QColor(0xFD, 0xD4, 0x9E, 0x60),
    ]

    def __init__(self, workspace, bitmap, base_addr, bits_inverted=False):
        self.workspace = workspace
        self.virgin_bitmap = bitmap
        if bits_inverted:
            # invert all bits
            self.virgin_bitmap = bytes([b ^ 0xFF for b in self.virgin_bitmap])
        self.bitmap_size = len(self.virgin_bitmap)
        assert self.bitmap_size == 1 << (self.bitmap_size.bit_length() - 1)
        self.function_info = {}
        self._hitcount_graphs = {}
        self._node_hitcounts = {}
        self._node_hitcount_summary = {}

        project = self.workspace.main_instance.project
        self.project_baddr = project.loader.main_object.mapped_base
        self.runtime_baddr = base_addr

        self._compute_hitcounts()

    def _compute_hitcounts(self):
        func_manager = self.workspace.main_instance.project.kb.functions
        for func_addr in func_manager:
            func = func_manager[func_addr]

            hitc_g = self._parse_bitmap(func)
            node_hitc = {n.addr: data["hitcount"] for n, data in hitc_g.nodes(data=True)}
            self._hitcount_graphs[func] = hitc_g
            self._node_hitcounts[func] = node_hitc
            for addr, hitcount in node_hitc.items():
                old = self._node_hitcount_summary.get(addr, 0)
                new = max(old, hitcount)
                self._node_hitcount_summary[addr] = new

    def get_hit_miss_color(self, addr):
        # TODO: sometimes there's addresses here that are not in the hitcount, don't know why
        hitcount = self._node_hitcount_summary.get(addr, 0)
        if hitcount == 0:
            return AFLQemuBitmap.MISS_COLOR
        else:
            return AFLQemuBitmap.HIT_COLOR

    def get_percent_color(self, func):
        if func.addr not in self.function_info:
            self._calc_function_info(func)

        return self.function_info[func.addr]["color"]

    def get_coverage(self, func):
        if func.addr not in self.function_info:
            self._calc_function_info(func)

        return self.function_info[func.addr]["coverage"]

    def get_any_trace(self, addr):
        raise NotImplementedError

    def runtime_to_project_addr(self, addr):
        return addr - self.runtime_baddr + self.project_baddr

    def project_to_runtime_addr(self, addr):
        return addr - self.project_baddr + self.runtime_baddr

    def addr_hash(self, addr):
        return ((addr >> 4) ^ (addr << 8)) & (self.bitmap_size - 1)

    def possible_dynamic_basic_block_succs(self, g, node):
        # we return two types of edges, may_takes and fallthroughs
        may_takes = []
        fallthroughs = []

        out_edges = g.out_edges(node, data=True)
        for _, dst, data in out_edges:
            type_ = data.get("type", "transition")
            if type_ == "fake_return":
                fallthroughs.append(dst)
            else:
                may_takes.append(dst)
        return may_takes, fallthroughs

    def _incoming_transition_edges(self, g, node):
        in_edges = g.in_edges(node, data=True)
        r = []
        for src, _, data in in_edges:
            type_ = data.get("type", "transition")
            if type_ in ("transition", "exception"):
                r.append((src, node))
        return r

    def _parse_bitmap(self, func):
        func_graph = func.transition_graph
        worklist = [(func.startpoint, None)]
        done = set()
        hitcount_graph = nx.DiGraph()
        while worklist:
            node, actual_addr = worklist.pop()
            if node in done:
                continue

            hitcount_graph.add_node(node)

            may_takes, fallthroughs = self.possible_dynamic_basic_block_succs(func_graph, node)
            if len(may_takes) == 1 and not fallthroughs:
                # a continuous block might be broken into two or more because of CFG normalization, without any
                # fallthrough edges.
                # if a covered block has only one possible successor, the successor will definitely be covered
                succ = may_takes[0]
                hitcount_graph.add_node(succ)
                hitcount_graph.add_edge(node, succ, hitcount=1)  # it may not be 1 but it's hard to figure out the real
                # number
                _l.debug("%r -> %r (single successor, no fallthrough)", node, succ)
                if len(self._incoming_transition_edges(func_graph, succ)) > 1:
                    _l.debug("... %r is probably a result of graph normalization.", succ)
                    worklist.append((succ, node.addr))  # the actual address for AFL address hashing is the address of
                    # node
                else:
                    _l.debug("... %r is the target of a jump.", succ)
                    worklist.append((succ, None))

                done.add(node)
                continue

            possible_node_addrs = [node.addr]
            if actual_addr is not None:
                possible_node_addrs.append(actual_addr)

            for node_addr in possible_node_addrs:
                added = False
                for succ in may_takes:
                    prev_loc = self.addr_hash(self.project_to_runtime_addr(node_addr)) >> 1
                    cur_loc = self.addr_hash(self.project_to_runtime_addr(succ.addr))

                    idx = prev_loc ^ cur_loc
                    hitc = self.virgin_bitmap[idx]
                    _l.debug("%#x -> %#x [%#x^%#x = %#x] = %#x", node.addr, succ.addr, prev_loc, cur_loc, idx, hitc)

                    if hitc > 0:
                        added = True
                        hitcount_graph.add_node(succ)
                        hitcount_graph.add_edge(node, succ, hitcount=hitc)
                        if not isinstance(succ, Function):
                            worklist.append((succ, None))
                if added:
                    # we guessed the correct address
                    break

            if fallthroughs:
                # this may be a call, which also must be taken, but the fallthrough edges may or may not be taken
                # depending on whether the program returned from the call or not
                for fallthrough in fallthroughs:
                    _l.debug("%r -?-> %r (fallthrough)", node, fallthrough)
                    worklist.append((fallthrough, None))

            done.add(node)

        for node in hitcount_graph.nodes():
            succ_hitcount = sum(data["hitcount"] for o, data in hitcount_graph.succ[node].items())
            pred_hitcount = sum(data["hitcount"] for o, data in hitcount_graph.pred[node].items())

            node_hitc = max(succ_hitcount, pred_hitcount)
            _l.debug("Marking node %r with hitcount %d", repr(node), node_hitc)
            hitcount_graph.nodes[node]["hitcount"] = node_hitc

        return hitcount_graph

    def _calc_function_info(self, func):
        node_hitcounts = self._node_hitcounts[func]

        block_addrs = list(func.block_addrs)
        hit_count = 0

        for block_addr in block_addrs:
            if block_addr not in node_hitcounts:
                # not hit at all
                continue

            if node_hitcounts[block_addr] > 0:
                hit_count += 1

        if hit_count == 0:
            self.function_info[func.addr] = {"color": AFLQemuBitmap.FUNCTION_NOT_VISITED_COLOR, "coverage": 0}
        elif hit_count == len(block_addrs):
            self.function_info[func.addr] = {"color": AFLQemuBitmap.HIT_COLOR, "coverage": 100}
        else:
            hit_percent = (hit_count / len(block_addrs)) * 100
            bucket_size = 100 / len(AFLQemuBitmap.BUCKET_COLORS)
            bucket_pos = math.floor(hit_percent / bucket_size)
            self.function_info[func.addr] = {"color": AFLQemuBitmap.BUCKET_COLORS[bucket_pos], "coverage": hit_percent}
