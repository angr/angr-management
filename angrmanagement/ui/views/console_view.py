from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QHBoxLayout
from traitlets.config.configurable import MultipleInstanceError

from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace

_l = logging.getLogger(name=__name__)


class ConsoleView(InstanceView):
    """
    Console view providing IPython interactive session.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("console", workspace, default_docking_position, instance)

        self.base_caption = "Console"
        self._ipython_widget = None

        if self.workspace.main_window.initialized:
            self.mainWindowInitializedEvent()

    @property
    def ipython_widget_available(self) -> bool:
        return self._ipython_widget is not None

    def mainWindowInitializedEvent(self) -> None:
        self._init_widgets()
        self.reload()

    def reload(self) -> None:
        if self._ipython_widget is None:
            return

        import angr  # pylint: disable=import-outside-toplevel,multiple-imports
        import claripy
        import cle

        namespace = {
            "angr": angr,
            "claripy": claripy,
            "cle": cle,
            "workspace": self.workspace,
            "instance": self.instance,
            "project": self.instance.project,
        }
        self._ipython_widget.push_namespace(namespace)

    def push_namespace(self, namespace) -> None:
        if self._ipython_widget is None:
            return

        self._ipython_widget.push_namespace(namespace)

    def print_text(self, msg) -> None:
        if self._ipython_widget is None:
            return

        self._ipython_widget.print_text(msg)

    def set_input_buffer(self, text: str) -> None:
        if self._ipython_widget is None:
            return
        self._ipython_widget.input_buffer = text

    @staticmethod
    def minimumSizeHint():
        return QSize(0, 50)

    def _init_widgets(self) -> None:
        import angr  # pylint: disable=import-outside-toplevel,multiple-imports
        import claripy
        import cle

        namespace = {
            "angr": angr,
            "claripy": claripy,
            "cle": cle,
        }

        from angrmanagement.ui.widgets.qipython_widget import QIPythonWidget  # pylint:disable=import-outside-toplevel

        try:
            ipython_widget = QIPythonWidget(namespace=namespace)
        except MultipleInstanceError:
            _l.warning(
                "Fails to load the Console view since an IPython interpreter has already been loaded. "
                "You might be running angr Management with IPython."
            )
            return

        self._ipython_widget = ipython_widget
        ipython_widget.executed.connect(self.command_executed)

        hlayout = QHBoxLayout()
        hlayout.addWidget(ipython_widget)
        hlayout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(hlayout)

    def command_executed(self, msg) -> None:
        if msg["msg_type"] == "execute_reply" and msg["content"]["status"] == "ok":
            view = self.workspace.view_manager.first_view_in_category("disassembly")
            if view is not None:
                view.refresh()

    def set_current_function(self, func) -> None:
        self.push_namespace(
            {
                "func": func,
                "function": func,
                "function_": func,  # deprecated
            }
        )
