from typing import List, Tuple, Optional

import PySide2.QtCore
from PySide2.QtCore import QSize, Qt
from PySide2.QtWidgets import QTreeWidget, QTreeWidgetItem, QHBoxLayout, QVBoxLayout

from angr.project import Project
from angr.knowledge_plugins.functions import Function
from angrmanagement.ui.views import BaseView

from ..data import ComponentTreeNode, ComponentTree, ComponentFunction


class QComponentItem(QTreeWidgetItem):
    def __init__(self, parent, component: ComponentTreeNode):
        super().__init__(parent)
        self.component = component

        if component.name:
            self.setText(0, component.name)
        else:
            self.setText(0, "Component")

        self.function_nodes: List[QFunctionItem] = [ ]


class QFunctionItem(QTreeWidgetItem):
    def __init__(self, project: Project, parent, comp_func: ComponentFunction, function: Optional[Function]=None):
        super().__init__(parent)

        self.project = project
        self.comp_func = comp_func
        self.function = function

        if self.function is not None:
            # matched!
            self.setText(0, self.function.demangled_name)
            self.setTextColor(0, Qt.darkGreen)
        else:
            # unmatched
            self.setText(0, hex(self.func_addr))
            self.setTextColor(0, Qt.red)

    @property
    def func_addr(self):
        return self.project.loader.main_object.mapped_base + self.comp_func.virtual_addr


class ComponentsView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('components', workspace, default_docking_position, *args, **kwargs)

        self.base_caption = "Components"
        self.width_hint = 100
        self.height_hint = 100

        self._tree: QTreeWidget = None

        self._init_widgets()

    def _init_widgets(self):
        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.itemDoubleClicked.connect(self.on_item_doubleclicked)

        layout = QVBoxLayout()
        layout.addWidget(self._tree)

        self.setLayout(layout)

    def minimumSizeHint(self) -> PySide2.QtCore.QSize:
        return QSize(100, 100)

    def load(self, tree: ComponentTree):
        """
        Display a component tree.
        """

        if self.workspace.instance.project.am_none:
            return
        proj = self.workspace.instance.project
        funcs = self.workspace.instance.kb.functions

        self._tree.clear()

        queue: List[Tuple[ComponentTreeNode,Optional[QComponentItem]]] = [(tree.root, None)]
        while queue:
            node, parent = queue.pop(0)

            if parent is None:
                # this is the root
                parent = self._tree

            # create a widget item
            item = QComponentItem(parent, node)
            # add all functions
            for comp_func in node.functions:
                try:
                    func = funcs.get_by_addr(proj.loader.main_object.mapped_base + comp_func.virtual_addr)
                except KeyError:
                    func = None
                func_node = QFunctionItem(self.workspace.instance.project, item, comp_func, function=func)
                item.function_nodes.append(func_node)
            # insert all components into the queue
            for comp in node.components:
                queue.append((
                    comp, item
                ))

    def reset(self):
        self._tree.clear()

    #
    # Event
    #

    def on_item_doubleclicked(self, item: QTreeWidgetItem, column: int):

        if isinstance(item, QFunctionItem):
            if item.function is not None:
                # display the function, either in the disassembly view or in the pseudo code view
                self.workspace.on_function_selected(item.function)
            else:
                # jump to the function address
                self.workspace.jump_to(item.func_addr)
