"""Graphs of boxes in character cells: converting an analysis graph, and laying boxes out as a graph or a tree."""

# pylint: disable=missing-class-docstring,no-self-use

from __future__ import annotations

import unittest

import networkx

from angrmanagement.present.graphs import GraphBox, TreeGraphPresenter, convert_graph, text_lines


class TestGraphs(unittest.TestCase):
    def graph(self) -> networkx.DiGraph:
        g = networkx.DiGraph()
        g.add_edges_from([("root", "left"), ("root", "right"), ("left", "leaf")])
        return g

    def test_convert_graph(self):
        g = convert_graph(self.graph(), lambda node, converted: None if node == "leaf" else node.upper())
        assert set(g.nodes()) == {"ROOT", "LEFT", "RIGHT"} and set(g.edges()) == {("ROOT", "LEFT"), ("ROOT", "RIGHT")}

    def check_picture(self, presenter: TreeGraphPresenter) -> None:
        picture = presenter.picture
        graph = presenter.graph_source()
        assert graph is not None
        assert len(picture.boxes) == graph.number_of_nodes() and len(picture.edges) == graph.number_of_edges()
        placed = list(picture.layout.items())
        for i, (a, (ax, ay)) in enumerate(placed):
            assert ax >= 0 and ay >= 0
            for b, (bx, by) in placed[i + 1 :]:
                overlap_x = ax < bx + b.width and bx < ax + a.width
                overlap_y = ay < by + b.height and by < ay + a.height
                assert not (overlap_x and overlap_y), (a.node, b.node)
        for edge in picture.edges:
            points = edge.points
            # orthogonal segments only
            for (x0, y0), (x1, y1) in zip(points, points[1:], strict=False):
                assert x0 == x1 or y0 == y1
            assert picture.box_at(*points[-1]) is None
        assert presenter.nodes()[0] == "root" or presenter.layouter == "tree"

    def test_graph_layout_in_cells(self):
        presenter = TreeGraphPresenter(self.graph, lambda node: text_lines([node, "x" * 3]))
        self.check_picture(presenter)
        box = presenter.picture.box_of("root")
        assert box is not None and (box.width, box.height) == (8, 4)
        assert presenter.picture.box_at(*presenter.picture.layout[box]) is box
        assert presenter.select_next(1) == presenter.nodes()[0]
        assert presenter.select_next(-1) == presenter.nodes()[-1]

    @staticmethod
    def even_tree() -> networkx.DiGraph:
        # every leaf as deep as the others, so each edge goes from one layer to the next
        g = networkx.DiGraph()
        g.add_edges_from([("root", "a"), ("root", "b"), ("a", "c"), ("b", "d")])
        return g

    def test_tree_layout_in_cells(self):
        presenter = TreeGraphPresenter(self.even_tree, lambda node: GraphBox(node, text_lines([node])), layouter="tree")
        self.check_picture(presenter)
        layout = {box.node: pos for box, pos in presenter.picture.layout.items()}
        # layers right to left: the root is right of its successors
        assert layout["root"][0] > layout["a"][0] > layout["c"][0]
        presenter_v = TreeGraphPresenter(
            self.even_tree, lambda node: GraphBox(node, text_lines([node])), layouter="tree", vertical=True
        )
        self.check_picture(presenter_v)
        layout = {box.node: pos for box, pos in presenter_v.picture.layout.items()}
        assert layout["root"][1] < layout["a"][1] < layout["c"][1]

    def test_no_graph(self):
        presenter = TreeGraphPresenter(lambda: None, lambda node: None)
        assert not presenter.picture.boxes and presenter.picture.size == (0, 0)
        assert presenter.select_next(1) is None


if __name__ == "__main__":
    unittest.main()
