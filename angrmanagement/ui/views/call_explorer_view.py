from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QFont, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QHBoxLayout, QHeaderView, QLabel, QTreeView, QTreeWidget, QVBoxLayout

from angrmanagement.config import Conf
from angrmanagement.logic.debugger import DebuggerWatcher
from angrmanagement.logic.debugger.bintrace import BintraceDebugger

from .view import InstanceView

if TYPE_CHECKING:
    from angr.knowledge_plugins import Function

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace

try:
    from bintrace import TraceEvent
except ImportError:
    TraceEvent = "TraceEvent"


class CallTreeModel(QStandardItemModel):
    """
    Model for the call tree.
    """

    Headers = ["Function"]

    def hasChildren(self, index):
        item: CallTreeItem | None = self.itemFromIndex(index)
        if isinstance(item, CallTreeItem):
            return item.expandable
        return super().hasChildren(index)

    def headerData(self, section, orientation, role):  # pylint:disable=unused-argument
        if role != Qt.DisplayRole:
            return None
        if section < len(self.Headers):
            return self.Headers[section]
        return None


class CallTreeItem(QStandardItem):
    """
    Item in call tree representing a function.
    """

    def __init__(self, function, event) -> None:
        name = hex(function) if isinstance(function, int) else function.name
        super().__init__(name)
        self.function: int | Function = function
        self.event: TraceEvent = event
        self.populated: bool = False
        self.expandable: bool = True


class CallExplorerView(InstanceView):
    """
    Call Explorer view.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("call_explorer", workspace, default_docking_position, instance)

        self._last_updated_func: int | Function | None = None
        self._inhibit_update: bool = False

        self.base_caption = "Call Explorer"
        self._tree: QTreeWidget | None = None
        self._init_widgets()
        self.reload()

        self.width_hint = 500
        self.height_hint = 400
        self.updateGeometry()

        self._dbg_manager = instance.debugger_mgr
        self._dbg_watcher = DebuggerWatcher(self._on_debugger_state_updated, self._dbg_manager.debugger)
        self._on_debugger_state_updated()

    @staticmethod
    def minimumSizeHint():
        return QSize(200, 200)

    def _init_widgets(self) -> None:
        vlayout = QVBoxLayout()
        vlayout.setSpacing(0)
        vlayout.setContentsMargins(0, 0, 0, 0)
        self._top_level_function_level = QLabel()
        self._reset_function_label()
        hlayout = QHBoxLayout()
        hlayout.addWidget(self._top_level_function_level)
        hlayout.setContentsMargins(3, 3, 3, 3)
        vlayout.addLayout(hlayout)
        self._tree = QTreeView(self)
        self._model = CallTreeModel(self._tree)
        self._tree.setModel(self._model)
        self._tree.setFont(QFont(Conf.disasm_font))
        header = self._tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self._tree.expanded.connect(self._on_item_expanded)
        self._tree.clicked.connect(self._on_item_clicked)
        self._tree.doubleClicked.connect(self._on_item_double_clicked)
        vlayout.addWidget(self._tree)
        self.setLayout(vlayout)

    #
    # Events
    #

    def closeEvent(self, event) -> None:
        self._dbg_watcher.shutdown()
        super().closeEvent(event)

    def _on_item_clicked(self, index) -> None:
        """
        Highlights the corresponding call site.
        """
        item = self._model.itemFromIndex(index)

        # Do not try to update on a single click. Allow user to browse through the call tree
        original_inhibit = self._inhibit_update
        self._inhibit_update = True

        # Replay up to just before call
        dbg = self.instance.debugger_mgr.debugger
        dbg.replay_to_event(dbg._btrace.get_prev_exec_event(item.event, vcpu=dbg._trace_dbg.vcpu))

        self._inhibit_update = original_inhibit

    def _on_item_double_clicked(self, index) -> None:
        """
        Navigates into the call.
        """
        item = self._model.itemFromIndex(index)
        # Replay after the jump, jumping into the called function
        # FIXME: Doesn't consider proper selected debugger, assumes bintrace
        dbg = self.instance.debugger_mgr.debugger
        dbg.replay_to_event(dbg._btrace.get_next_exec_event(item.event, vcpu=dbg._trace_dbg.vcpu))

    def _on_item_expanded(self, index) -> None:
        """
        Descend into call tree for this node.
        """
        expanding_item = self._model.itemFromIndex(index)
        if not expanding_item.populated:
            dbg = self.instance.debugger_mgr.debugger
            if dbg.am_none:
                return
            called = dbg.get_called_functions(expanding_item.event)
            for func_or_addr, event in called:
                expanding_item.appendRow(CallTreeItem(func_or_addr, event))
            expanding_item.expandable = len(called) > 0
            expanding_item.populated = True

    def _on_debugger_state_updated(self) -> None:
        """
        Update current call state.
        """
        if self._inhibit_update:
            return

        dbg = self._dbg_watcher.debugger
        if isinstance(dbg.am_obj, BintraceDebugger):
            func = dbg.get_current_function()
            if func is not None:
                func = func[0]
        else:
            func = None

        if func is self._last_updated_func:
            return

        self._model.clear()
        self._last_updated_func = func

        if func is not None and isinstance(dbg.am_obj, BintraceDebugger):
            self._top_level_function_level.setText(f"Current function: {func.name}")
            for func, event in dbg.get_called_functions():
                self._model.appendRow(CallTreeItem(func, event))
        else:
            self._reset_function_label()

    def _reset_function_label(self) -> None:
        self._top_level_function_level.setText("Current function: Unknown")
