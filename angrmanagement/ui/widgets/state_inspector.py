from PySide.QtGui import QTabWidget
from angrmanagement.ui.widgets.qmemory_viewer import QMemoryViewer
from angrmanagement.ui.widgets.qregister_viewer import QRegisterViewer
from angrmanagement.ui.widgets.qvextemps_viewer import QVEXTempsViewer


class StateInspector(QTabWidget):
    def __init__(self, workspace, state, parent=None):
        super(StateInspector, self).__init__(parent=parent)
        self.workspace = workspace
        self._state = state

        self._register_viewer = None  # type: QRegisterViewer
        self._memory_viewer = None  # type: QMemoryViewer
        self._vextemps_viewer = None  # type: QVEXTempsViewer

        self._init_widgets()

    def _init_widgets(self):
        self._register_viewer = QRegisterViewer(self._state, self, self.workspace)
        self.addTab(self._register_viewer, "Registers")

        self._memory_viewer = QMemoryViewer(self._state, self, self.workspace)
        self.addTab(self._memory_viewer, "Memory")

        self._vextemps_viewer = QVEXTempsViewer(self._state, self, self.workspace)
        self.addTab(self._vextemps_viewer, "Temps")
