"""
The Source Viewer plugin's entry point. It imports no toolkit, so the plugin activates in the terminal without PySide6;
the Qt view (source_viewer_plugin.py) is imported only in the Qt frontend.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.plugins import BasePlugin
from angrmanagement.plugins.base_plugin import qt_frontend

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class SourceViewerPlugin(BasePlugin):
    """
    Shows the binary's source files beside the disassembly: the Qt SourceViewer, or SourceTuiView in the terminal.
    """

    def __init__(self, workspace: Workspace) -> None:
        super().__init__(workspace)
        if qt_frontend():
            from .source_viewer_plugin import SourceViewer  # pylint:disable=import-outside-toplevel

            self.source_viewer = SourceViewer(workspace)
            workspace.default_tabs += [self.source_viewer]
        else:
            from .tui_view import SourceTuiView  # pylint:disable=import-outside-toplevel

            self.source_viewer = SourceTuiView(workspace, "center", workspace.main_instance)
        workspace.add_view(self.source_viewer)

    def teardown(self) -> None:
        if self.workspace is not None:
            self.workspace.remove_view(self.source_viewer)
