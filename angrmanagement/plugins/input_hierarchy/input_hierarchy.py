import os

import networkx as nx
import phuzzer
from PySide2.QtCore import Qt, QPointF, QRectF
from PySide2.QtWidgets import QMainWindow, QVBoxLayout, QGraphicsItem, QMessageBox
from PySide2.QtGui import QColor, QPen, QFont

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.views import BaseView
from angrmanagement.ui.widgets.qgraph import QZoomableDraggableGraphicsView
from angrmanagement.ui.widgets.qgraph_arrow import QGraphArrow
from angrmanagement.utils.graph_layouter import GraphLayouter


class Node(QGraphicsItem):
    def __init__(self, data, *, graph):
        super().__init__()
        self.data = data
        self.graph = graph
        self.addr = hash(data)  # Needed for GraphLayouter, ultimately used to sort

        num_successors = len(list(self.graph.successors(self.data)))

        self.width = 50 + 5 * num_successors
        self.height = 50 + 5 * num_successors

    @property
    def color(self):
        if self.data.crash:
            return QColor(255, 0, 0)
        if self.data.cov:
            return QColor(0, 255, 0)
        return QColor(220, 220, 220)

    def paint(self, painter, option, widget):
        painter.setBrush(self.color)
        painter.drawRect(0, 0, self.width, self.height)

    def boundingRect(self):
        return QRectF(0, 0, self.width, self.height)

    def mousePressEvent(self, event):  # DEBBUG: remove
        if event.button() == Qt.LeftButton:
            global workspace_global
            workspace_global.node = self
            event.accept()
        super().mousePressEvent(event)


class InputHierarchyView(BaseView):
    def __init__(self, *args, **kwargs):
        super().__init__("graph", *args, **kwargs)
        self.caption = "Input Hierarchy"

        self.canvas = QZoomableDraggableGraphicsView()
        self.canvas._reset_scene()

        main_layout = QVBoxLayout()
        main = QMainWindow()

        main.setWindowFlags(Qt.Widget)
        main.setCentralWidget(self.canvas)
        main_layout.addWidget(main)

        self.setLayout(main_layout)

    def graph(self, graph):
        mapping = {node: Node(node, graph=graph) for node in graph.nodes()}
        qgraph = nx.relabel_nodes(graph, mapping)

        node_sizes = {node: (node.width, node.height) for node in qgraph.nodes()}
        layout = GraphLayouter(qgraph, node_sizes)

        scene = self.canvas.scene()

        for edge in layout.edges:
            arrow = QGraphArrow(edge)
            arrow.setPos(QPointF(*edge.coordinates[0]))
            scene.addItem(arrow)

        for node, (x, y) in layout.node_coordinates.items():
            node.setPos(x, y)
            scene.addItem(node)

        rect = scene.itemsBoundingRect()
        scene.setSceneRect(
            QRectF(
                rect.x() - 200, rect.y() - 200, rect.width() + 400, rect.height() + 400,
            )
        )


class InputHierarchyPlugin(BasePlugin):
    def __init__(self, workspace, *args, **kwargs):
        super().__init__(workspace, *args, **kwargs)

        self.hierarchy_view = InputHierarchyView(workspace, "center")

        workspace.default_tabs += [self.hierarchy_view]
        workspace.add_view(
            self.hierarchy_view,
            self.hierarchy_view.caption,
            self.hierarchy_view.category,
        )

        global workspace_global  # DEBBUG: remove
        workspace_global = workspace  # DEBBUG: remove

        fuzz_path = os.getenv("FUZZ_PATH")
        if not fuzz_path:
            raise Exception("No FUZZ_PATH environment variable specified")

        graph = phuzzer.InputHierarchy(fuzz_path).make_graph()

        remove = [
            node
            for node in graph.nodes()
            if not node.cov and not node.crash and graph.out_degree(node) == 0
        ]
        graph.remove_nodes_from(remove)

        remove = [node for node in graph.nodes() if graph.out_degree(node) == 0]
        graph.remove_nodes_from(remove)

        workspace.fuzzer_graph = graph

        self.hierarchy_view.graph(graph)
