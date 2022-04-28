import logging
from typing import Optional, Union

from PySide2.QtGui import QFont, QStandardItemModel, QStandardItem
from PySide2.QtCore import QSize, Qt
from PySide2.QtWidgets import QHeaderView, QVBoxLayout, QTreeWidget, QTreeView, QLabel
from angr.knowledge_plugins import Function

try:
    from bintrace import TraceEvent
except ImportError as e:
    TraceEvent = 'TraceEvent'

from ...logic.debugger.bintrace import BintraceDebugger
from ...logic.debugger import DebuggerWatcher
from ...config import Conf
from .view import BaseView


_l = logging.getLogger(name=__name__)


class CallTreeModel(QStandardItemModel):
    """
    Model for the call tree.
    """
    Headers = ['Function']

    def hasChildren(self, index):
        item: Optional['CallTreeItem'] = self.itemFromIndex(index)
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

    def __init__(self, function, event):
        name = hex(function) if isinstance(function, int) else function.name
        super().__init__(name)
        self.function: Union[int, Function] = function
        self.event: TraceEvent = event
        self.populated: bool = False
        self.expandable: bool = True


class CallExplorerView(BaseView):
    """
    Call Explorer view.
    """

    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('call_explorer', workspace, default_docking_position, *args, **kwargs)

        self._last_updated_func: Optional[Union[int, Function]] = None
        self._inhibit_update: bool = False

        self.base_caption = 'Call Explorer'
        self._tree: Optional[QTreeWidget] = None
        self._init_widgets()
        self.reload()

        self.width_hint = 500
        self.height_hint = 400
        self.updateGeometry()

        self._dbg_manager = workspace.instance.debugger_mgr
        self._dbg_watcher = DebuggerWatcher(self._on_debugger_state_updated, self._dbg_manager.debugger)
        self._on_debugger_state_updated()

    @staticmethod
    def minimumSizeHint(*args, **kwargs):  # pylint:disable=unused-argument
        return QSize(200, 200)

    def _init_widgets(self):
        vlayout = QVBoxLayout()
        self._top_level_function_level = QLabel()
        self._reset_function_label()
        vlayout.addWidget(self._top_level_function_level)
        self._tree = QTreeView(self)
        self._model = CallTreeModel(self._tree)
        self._tree.setModel(self._model)
        self._tree.setFont(QFont(Conf.disasm_font))
        header = self._tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        self._tree.expanded.connect(self._on_item_expanded)
        self._tree.clicked.connect(self._on_item_clicked)
        self._tree.doubleClicked.connect(self._on_item_double_clicked)
        vlayout.addWidget(self._tree)
        self.setLayout(vlayout)

    #
    # Events
    #

    def closeEvent(self, event):
        self._dbg_watcher.shutdown()
        super().closeEvent(event)

    def _on_item_clicked(self, index):
        """
        Highlights the corresponding call site.
        """
        item = self._model.itemFromIndex(index)

        # Do not try to update on a single click. Allow user to browse through the call tree
        original_inhibit = self._inhibit_update
        self._inhibit_update = True

        # Replay up to just before call
        dbg = self.workspace.instance.debugger_mgr.debugger
        dbg.replay_to_event(dbg._btrace.get_prev_exec_event(item.event, vcpu=dbg._trace_dbg.vcpu))

        self._inhibit_update = original_inhibit

    def _on_item_double_clicked(self, index):
        """
        Navigates into the call.
        """
        item = self._model.itemFromIndex(index)
        # Replay after the jump, jumping into the called function
        # FIXME: Doesn't consider proper selected debugger, assumes bintrace
        dbg = self.workspace.instance.debugger_mgr.debugger
        dbg.replay_to_event(dbg._btrace.get_next_exec_event(item.event, vcpu=dbg._trace_dbg.vcpu))

    def _on_item_expanded(self, index):
        """
        Descend into call tree for this node.
        """
        expanding_item = self._model.itemFromIndex(index)
        if not expanding_item.populated:
            dbg = self.workspace.instance.debugger_mgr.debugger
            if dbg.am_none:
                return
            called = dbg.get_called_functions(expanding_item.event)
            for func_or_addr, event in called:
                expanding_item.appendRow(CallTreeItem(func_or_addr, event))
            expanding_item.expandable = len(called) > 0
            expanding_item.populated = True

    def _on_debugger_state_updated(self):
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
            self._top_level_function_level.setText(f'Current function: {func.name}')
            for func, event in dbg.get_called_functions():
                self._model.appendRow(CallTreeItem(func, event))
        else:
            self._reset_function_label()

    def _reset_function_label(self):
        self._top_level_function_level.setText('Current function: Unknown')
