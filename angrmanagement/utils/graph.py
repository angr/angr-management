
import itertools

import networkx

from angr.knowledge import Function


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

    edges_to_shrink = set()

    # Find all edges to remove in the super graph
    for n in transition_graph.nodes_iter():
        edges = transition_graph[n]

        if any(iter('type' in data and data['type'] not in ('fake_return', 'call') for data in edges.values())):
            continue

        for dst, data in edges.iteritems():
            if isinstance(dst, Function):
                continue
            if 'type' in data and data['type'] == 'fake_return':
                if all(iter('type' in data and data['type'] in ('fake_return', 'return_from_call')
                            for _, _, data in transition_graph.in_edges(dst, data=True))):
                    edges_to_shrink.add((n, dst))
                break

    # Create the super graph
    super_graph = networkx.DiGraph()

    supernodes_map = {}

    function_nodes = set()  # it will be traversed after all other nodes are added into the supergraph

    for node in transition_graph.nodes_iter():

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

        for dst, data in dests_and_data.iteritems():

            edge = (node, dst)

            if edge in edges_to_shrink:

                if dst in supernodes_map:
                    dst_supernode = supernodes_map[dst]
                else:
                    dst_supernode = None

                src_supernode.insert_cfgnode(dst)

                # update supernodes map
                supernodes_map[dst] = src_supernode

                # merge the other supernode
                if dst_supernode is not None:
                    src_supernode.merge(dst_supernode)

                    for n in dst_supernode.cfg_nodes:
                        supernodes_map[n] = src_supernode

                    # link all out edges of dst_supernode to src_supernode
                    for dst_, data_ in super_graph[dst_supernode].iteritems():
                        super_graph.add_edge(src_supernode, dst_, **data_)

                    # link all in edges of dst_supernode to src_supernode
                    for src_, _, data_ in super_graph.in_edges([dst_supernode], data=True):
                        super_graph.add_edge(src_, src_supernode, **data_)

                        if 'type' in data_ and data_['type'] == 'transition':
                            src_supernode.register_out_branch(data_['ins_addr'], data_['stmt_idx'], data_['type'],
                                                              dst_supernode.addr
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

                if 'type' in data and data['type'] == 'transition':
                    src_supernode.register_out_branch(data['ins_addr'], data['stmt_idx'], data['type'],
                                                      dst_supernode.addr
                                                      )

    for node in function_nodes:
        in_edges = transition_graph.in_edges(node, data=True)

        for src, _, data in in_edges:
            supernode = supernodes_map[src]
            supernode.register_out_branch(data['ins_addr'], data['stmt_idx'], data['type'], node.addr)

    return super_graph


class OutBranch(object):
    def __init__(self, ins_addr, stmt_idx, branch_type):
        self.ins_addr = ins_addr
        self.stmt_idx = stmt_idx
        self.type = branch_type

        self.targets = set()

    def add_target(self, addr):
        self.targets.add(addr)

    def merge(self, other):
        """
        Merge with the other OutBranch descriptor.

        :param OutBranch other: The other item to merge with.
        :return: None
        """

        assert self.ins_addr == other.ins_addr
        assert self.stmt_idx == other.stmt_idx
        assert self.type == other.type

        self.targets |= other.targets


class SuperCFGNode(object):
    def __init__(self, addr):
        self.addr = addr

        self.cfg_nodes = [ ]

        self.out_branches = { }

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
        if ins_addr not in self.out_branches:
            self.out_branches[ins_addr] = OutBranch(ins_addr, stmt_idx, branch_type)

        self.out_branches[ins_addr].add_target(target_addr)

    def merge(self, other):
        """
        Merge another supernode into the current one.

        :param SuperCFGNode other: The supernode to merge with.
        :return: None
        """

        for n in other.cfg_nodes:
            self.insert_cfgnode(n)

        for addr, item in other.out_branches.iteritems():
            if addr in self.out_branches:
                self.out_branches[addr].merge(item)
            else:
                self.out_branches[addr] = item

    def __repr__(self):
        return "<SuperCFGNode %#08x, %d blocks, %d out branches>" % (self.addr, len(self.cfg_nodes),
                                                                     len(self.out_branches)
                                                                     )
