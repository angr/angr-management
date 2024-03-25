from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QTabWidget

from .qconstraint_viewer import QConstraintViewer
from .qfiledesc_viewer import QFileDescriptorViewer
from .qmemory_viewer import QMemoryViewer
from .qregister_viewer import QRegisterViewer
from .qvextemps_viewer import QVEXTempsViewer

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class StateInspector(QTabWidget):
    """
    Dispaly detail information for a selected state.
    """

    def __init__(self, workspace: Workspace, state, parent=None) -> None:
        super().__init__(parent=parent)
        self.workspace = workspace
        self._state = state

        self._register_viewer: QRegisterViewer
        self._memory_viewer: QMemoryViewer
        self._vextemps_viewer: QVEXTempsViewer
        self._constraint_viewer: QConstraintViewer
        self._filedesc_viewer: QFileDescriptorViewer

        self._init_widgets()

    def _init_widgets(self) -> None:
        self._register_viewer = QRegisterViewer(self._state, self, self.workspace)
        self.addTab(self._register_viewer, "Registers")

        self._memory_viewer = QMemoryViewer(self._state, self, self.workspace)
        self.addTab(self._memory_viewer, "Memory")

        self._constraint_viewer = QConstraintViewer(self._state, self, self.workspace)
        self.addTab(self._constraint_viewer, "Constraints")

        self._filedesc_viewer = QFileDescriptorViewer(self._state, self, self.workspace)
        self.addTab(self._filedesc_viewer, "File Descriptors")

        self._vextemps_viewer = QVEXTempsViewer(self._state, self, self.workspace)
        self.addTab(self._vextemps_viewer, "Temps")
