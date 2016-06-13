
import itertools

import networkx

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
        if transition_graph.out_degree(n) == 1:
            edges = transition_graph[n]
            dst, data = edges.items()[0]
            if 'type' in data and data['type'] == 'fake_return':
                if all(iter('type' in data and data['type'] in ('fake_return', 'return_from_call')
                            for _, _, data in transition_graph.in_edges(dst, data=True))):
                    edges_to_shrink.add((n, dst))
                continue
        elif transition_graph.out_degree(n) == 2:
            edges = transition_graph[n]

            if any(iter('type' in data and data['type'] not in ('fake_return', 'call') for data in edges.values())):
                continue

            for dst, data in edges.iteritems():
                if 'type' in data and data['type'] == 'fake_return':
                    if all(iter('type' in data and data['type'] in ('fake_return', 'return_from_call')
                                for _, _, data in transition_graph.in_edges(dst, data=True))):
                        edges_to_shrink.add((n, dst))
                    break

    # Create the super graph
    super_graph = networkx.DiGraph()

    supernodes_map = {}

    for node in transition_graph.nodes_iter():
        dests_and_data = transition_graph[node]

        # make a super node
        if node in supernodes_map:
            src_supernode = supernodes_map[node]
        else:
            src_supernode = SuperCFGNode.from_cfgnode(node)
            supernodes_map[node] = src_supernode

        if not dests_and_data:
            # an isolated node
            super_graph.add_node(SuperCFGNode.from_cfgnode(node))
            continue

        for edge in ((node, dst) for dst, _ in dests_and_data.iteritems()):

            if edge in edges_to_shrink:

                dst = edge[1]

                if dst in supernodes_map:
                    dst_supernode = supernodes_map[dst]
                else:
                    dst_supernode = None

                src_supernode.insert_cfgnode(dst)

                # update supernodes map
                supernodes_map[dst] = src_supernode

                # merge the other supernode
                if dst_supernode is not None:
                    for n in dst_supernode.cfg_nodes:
                        src_supernode.insert_cfgnode(n)
                        supernodes_map[n] = src_supernode

                    # link all out edges of dst_supernode to src_supernode
                    for dst_, data_ in super_graph[dst_supernode].iteritems():
                        super_graph.add_edge(src_supernode, dst_, **data_)

                    super_graph.remove_node(dst_supernode)

                # insert it into the graph
                super_graph.add_node(src_supernode)

                break

        else:
            # insert all edges to our graph as usual
            for dst, data in dests_and_data.iteritems():
                # make a super node
                if dst in supernodes_map:
                    dst_supernode = supernodes_map[dst]
                else:
                    dst_supernode = SuperCFGNode.from_cfgnode(dst)
                    supernodes_map[dst] = dst_supernode

                super_graph.add_edge(src_supernode, dst_supernode, **data)

    return super_graph

class SuperCFGNode(object):
    def __init__(self, addr):
        self.addr = addr

        self.cfg_nodes = [ ]

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

    def __repr__(self):
        return "<SuperCFGNode %#08x, %d blocks>" % (self.addr, len(self.cfg_nodes))
