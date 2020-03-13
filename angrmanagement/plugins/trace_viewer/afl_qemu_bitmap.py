import math
import networkx as nx
import json

from PySide2.QtGui import QColor

def debug_show(*args, **kwargs):
    # print(*args, **kwargs)
    return

class AFLQemuBitmap:

    HIT_COLOR = QColor(0xee, 0xff, 0xee)
    MISS_COLOR = QColor(0x99, 0x00, 0x00, 0x30)
    FUNCTION_NOT_VISITED_COLOR = QColor(0x99, 0x00, 0x00, 0x20)
    BUCKET_COLORS = [QColor(0xef, 0x65, 0x48, 0x20), QColor(0xfc, 0x8d, 0x59, 0x60),
                     QColor(0xfd, 0xbb, 0x84, 0x60), QColor(0xfd, 0xd4, 0x9e, 0x60)]

    def __init__(self, workspace, bitmap, base_addr):
        self.workspace = workspace
        self.virgin_bitmap = bitmap
        self.bitmap_size = len(self.virgin_bitmap)
        assert self.bitmap_size == 1 << (self.bitmap_size.bit_length() - 1)
        self.function_info = {}
        self._hitcount_graphs = {}
        self._node_hitcounts = {}
        self._node_hitcount_summary = {}

        project = self.workspace.instance.project
        self.project_baddr = project.loader.main_object.mapped_base
        self.runtime_baddr = base_addr

        self._compute_hitcounts()

    def _compute_hitcounts(self):
        func_manager = self.workspace.instance.project.kb.functions
        for func_addr in func_manager:
            func = func_manager[func_addr]

            hitc_g = self._parse_bitmap(func)
            node_hitc = {n.addr: data['hitcount'] for n, data in hitc_g.nodes(data=True)}
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
        # We want to have this probably, but for now the other thing works too, so /shrug
        '''
        succs = list(g.successors(node))
        if len(succs) == 0:
            return [node]
        elif len(succs) == 1:
            # the case where we have a single block loop, need to be careful with this one
            return succs if node == succs[0] else self.possible_dynamic_basic_block_succs(g, succs[0])
        else:
            return succs
        '''
        return list(g.successors(node))

    def _parse_bitmap(self, func):
        func_graph = func.transition_graph
        worklist = [func.startpoint]
        done = set()
        hitcount_graph = nx.DiGraph()
        while worklist:
            node = worklist.pop()
            if node in done:
                continue

            hitcount_graph.add_node(node)

            prev_loc = self.addr_hash(self.project_to_runtime_addr(node.addr)) >> 1
            for succ in self.possible_dynamic_basic_block_succs(func_graph, node):
                cur_loc = self.addr_hash(self.project_to_runtime_addr(succ.addr))

                idx = prev_loc ^ cur_loc
                hitc = self.virgin_bitmap[idx] ^ 0xff
                debug_show("{:x} -> {:x} [{:x}^{:x} = {:x}] = {:x}".format(node.addr, succ.addr, prev_loc, cur_loc, idx, hitc))

                hitcount_graph.add_node(succ)
                hitcount_graph.add_edge(node, succ, hitcount=hitc)
                worklist.append(succ)

            done.add(node)

        for node in hitcount_graph.nodes():
            succ_hitcount = sum(data['hitcount'] for o, data in hitcount_graph.succ[node].items())
            pred_hitcount = sum(data['hitcount'] for o, data in hitcount_graph.pred[node].items())

            node_hitc = max(succ_hitcount, pred_hitcount)
            debug_show("Marking node {} with hitcount {}".format(node, node_hitc))
            hitcount_graph.nodes[node]['hitcount'] = node_hitc

        return hitcount_graph

    def _calc_function_info(self, func):
        node_hitcounts = self._node_hitcounts[func]

        block_addrs = list(func.block_addrs)
        hit_count = 0

        for block_addr in block_addrs:
            if block_addr not in node_hitcounts:
                print("WARNING WARNING: Why is block {} not in the node hitcounts when it's part of function {}???".format(block_addr, func))
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
