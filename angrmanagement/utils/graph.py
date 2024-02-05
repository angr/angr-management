import itertools
from collections import defaultdict

import networkx
from angr.knowledge_plugins import Function


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    args = [iter(iterable)] * n
    return itertools.izip_longest(*args, fillvalue=fillvalue)


def to_supergraph(transition_graph):
    """
    Convert transition graph of a function to a super transition graph. A super transition graph is a graph that looks
    like IDA Pro's CFG, where calls to returning functions do not terminate basic blocks.

    :param networkx.DiGraph transition_graph: The transition graph.
    :return: A converted super transition graph
    :rtype networkx.DiGraph
    """

    # make a copy of the graph
    transition_graph = networkx.DiGraph(transition_graph)

    # remove all edges that transitions to outside
    for src, dst, data in list(transition_graph.edges(data=True)):
        if data["type"] in ("transition", "exception") and data.get("outside", False) is True:
            transition_graph.remove_edge(src, dst)
        if transition_graph.in_degree(dst) == 0:
            transition_graph.remove_node(dst)

    edges_to_shrink = set()

    # Find all edges to remove in the super graph
    for src in transition_graph.nodes():
        edges = transition_graph[src]

        # there are two types of edges we want to remove:
        # - call or fakerets, since we do not want blocks to break at calls
        # - boring jumps that directly transfer the control to the block immediately after the current block. this is
        #   usually caused by how VEX breaks down basic blocks, which happens very often in MIPS

        if len(edges) == 1 and src.addr + src.size == next(iter(edges.keys())).addr:
            dst = next(iter(edges.keys()))
            dst_in_edges = transition_graph.in_edges(dst)
            if len(dst_in_edges) == 1:
                edges_to_shrink.add((src, dst))
                continue

        if any(iter("type" in data and data["type"] not in ("fake_return", "call") for data in edges.values())):
            continue

        for dst, data in edges.items():
            if isinstance(dst, Function):
                continue
            if "type" in data and data["type"] == "fake_return":
                if all(
                    iter(
                        "type" in data and data["type"] in ("fake_return", "return")
                        for _, _, data in transition_graph.in_edges(dst, data=True)
                    )
                ):
                    edges_to_shrink.add((src, dst))
                break

    # Create the super graph
    super_graph = networkx.DiGraph()

    supernodes_map = {}

    function_nodes = set()  # it will be traversed after all other nodes are added into the supergraph

    for node in transition_graph.nodes():
        if isinstance(node, Function):
            function_nodes.add(node)
            # don't put functions into the supergraph
            continue

        dests_and_data = transition_graph[node]

        # make a super node
        if node in supernodes_map:
            src_supernode = supernodes_map[node]
        else:
            src_supernode = SuperCFGNode.from_cfgnode(node)
            supernodes_map[node] = src_supernode
            # insert it into the graph
            super_graph.add_node(src_supernode)

        if not dests_and_data:
            # might be an isolated node
            continue

        # Take src_supernode off the graph since we might modify it
        if src_supernode in super_graph:
            existing_in_edges = list(super_graph.in_edges(src_supernode, data=True))
            existing_out_edges = list(super_graph.out_edges(src_supernode, data=True))
            super_graph.remove_node(src_supernode)
        else:
            existing_in_edges = []
            existing_out_edges = []

        for dst, data in dests_and_data.items():
            edge = (node, dst)

            if edge in edges_to_shrink:
                dst_supernode = supernodes_map.get(dst)

                src_supernode.insert_cfgnode(dst)

                # update supernodes map
                supernodes_map[dst] = src_supernode

                # merge the other supernode
                if dst_supernode is not None:
                    src_supernode.merge(dst_supernode)

                    for src in dst_supernode.cfg_nodes:
                        supernodes_map[src] = src_supernode

                    # link all out edges of dst_supernode to src_supernode
                    for dst_, data_ in super_graph[dst_supernode].items():
                        super_graph.add_edge(src_supernode, dst_, **data_)

                    # link all in edges of dst_supernode to src_supernode
                    for src_, _, data_ in super_graph.in_edges(dst_supernode, data=True):
                        super_graph.add_edge(src_, src_supernode, **data_)

                        if "type" in data_ and data_["type"] in {"transition", "exception", "call"}:
                            if not ("ins_addr" in data_ and "stmt_idx" in data_):
                                # this is a hack to work around the issue in Function.normalize() where ins_addr and
                                # stmt_idx weren't properly set onto edges
                                continue
                            src_supernode.register_out_branch(
                                data_["ins_addr"], data_["stmt_idx"], data_["type"], dst_supernode.addr
                            )

                    super_graph.remove_node(dst_supernode)

            else:
                if isinstance(dst, Function):
                    # skip all functions
                    continue

                # make a super node
                if dst in supernodes_map:
                    dst_supernode = supernodes_map[dst]
                else:
                    dst_supernode = SuperCFGNode.from_cfgnode(dst)
                    supernodes_map[dst] = dst_supernode

                super_graph.add_edge(src_supernode, dst_supernode, **data)

                if "type" in data and data["type"] in {"transition", "exception", "call"}:
                    if not ("ins_addr" in data and "stmt_idx" in data):
                        # this is a hack to work around the issue in Function.normalize() where ins_addr and
                        # stmt_idx weren't properly set onto edges
                        continue
                    src_supernode.register_out_branch(
                        data["ins_addr"], data["stmt_idx"], data["type"], dst_supernode.addr
                    )

        # add back the node (in case there are no edges)
        super_graph.add_node(src_supernode)
        # add back the old edges
        for src, _, data in existing_in_edges:
            super_graph.add_edge(src, src_supernode, **data)
        for _, dst, data in existing_out_edges:
            super_graph.add_edge(src_supernode, dst, **data)

    for node in function_nodes:
        in_edges = transition_graph.in_edges(node, data=True)

        for src, _, data in in_edges:
            if not ("ins_addr" in data and "stmt_idx" in data):
                # this is a hack to work around the issue in Function.normalize() where ins_addr and
                # stmt_idx weren't properly set onto edges
                continue
            supernode = supernodes_map[src]
            supernode.register_out_branch(data["ins_addr"], data["stmt_idx"], data["type"], node.addr)

    return super_graph


class OutBranch:
    def __init__(self, ins_addr, stmt_idx, branch_type):
        self.ins_addr = ins_addr
        self.stmt_idx = stmt_idx
        self.type = branch_type

        self.targets = set()

    def __repr__(self):
        if self.ins_addr is None:
            return "<OutBranch at None, type %s>" % self.type
        return f"<OutBranch at {self.ins_addr:#x}, type {self.type}>"

    def add_target(self, addr):
        self.targets.add(addr)

    def merge(self, other):
        """
        Merge with the other OutBranch descriptor.

        :param OutBranch other: The other item to merge with.
        :return: None
        """

        assert self.ins_addr == other.ins_addr
        assert self.type == other.type

        o = self.copy()
        o.targets |= other.targets

        return o

    def copy(self):
        o = OutBranch(self.ins_addr, self.stmt_idx, self.type)
        o.targets = self.targets.copy()
        return o

    def __eq__(self, other):
        if not isinstance(other, OutBranch):
            return False

        return (
            self.ins_addr == other.ins_addr
            and self.stmt_idx == other.stmt_idx
            and self.type == other.type
            and self.targets == other.targets
        )

    def __hash__(self):
        return hash((self.ins_addr, self.stmt_idx, self.type))


class SuperCFGNode:
    def __init__(self, addr, idx=None):
        self.addr = addr
        self.idx = idx

        self.cfg_nodes = []

        self.out_branches = defaultdict(dict)

    @property
    def size(self):
        return sum(node.size for node in self.cfg_nodes)

    @classmethod
    def from_cfgnode(cls, cfg_node):
        s = cls(cfg_node.addr)

        s.cfg_nodes.append(cfg_node)

        return s

    def insert_cfgnode(self, cfg_node):
        # TODO: Make it binary search/insertion
        for i, n in enumerate(self.cfg_nodes):
            if cfg_node.addr < n.addr:
                # insert before n
                self.cfg_nodes.insert(i, cfg_node)
                break
            elif cfg_node.addr == n.addr:
                break
        else:
            self.cfg_nodes.append(cfg_node)

        # update addr
        self.addr = self.cfg_nodes[0].addr

    def register_out_branch(self, ins_addr, stmt_idx, branch_type, target_addr):
        if ins_addr not in self.out_branches or stmt_idx not in self.out_branches[ins_addr]:
            self.out_branches[ins_addr][stmt_idx] = OutBranch(ins_addr, stmt_idx, branch_type)

        self.out_branches[ins_addr][stmt_idx].add_target(target_addr)

    def merge(self, other):
        """
        Merge another supernode into the current one.

        :param SuperCFGNode other: The supernode to merge with.
        :return: None
        """

        for n in other.cfg_nodes:
            self.insert_cfgnode(n)

        for ins_addr, outs in other.out_branches.items():
            if ins_addr in self.out_branches:
                for stmt_idx, item in outs.items():
                    if stmt_idx in self.out_branches[ins_addr]:
                        self.out_branches[ins_addr][stmt_idx].merge(item)
                    else:
                        self.out_branches[ins_addr][stmt_idx] = item

            else:
                item = next(iter(outs.values()))
                self.out_branches[ins_addr][item.stmt_idx] = item

    def __repr__(self):
        return "<SuperCFGNode %#08x, %d blocks, %d out branches>" % (
            self.addr,
            len(self.cfg_nodes),
            len(self.out_branches),
        )

    def __hash__(self):
        return hash(("supercfgnode", self.addr))

    def __eq__(self, other):
        if not isinstance(other, SuperCFGNode):
            return False

        return self.addr == other.addr
