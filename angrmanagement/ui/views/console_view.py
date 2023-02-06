import logging

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QHBoxLayout
from traitlets.config.configurable import MultipleInstanceError

from .view import BaseView

_l = logging.getLogger(name=__name__)


class ConsoleView(BaseView):
    """
    Console view providing IPython interactive session.
    """

    def __init__(self, instance, default_docking_position, *args, **kwargs):
        super().__init__("console", instance, default_docking_position, *args, **kwargs)

        self.base_caption = "Console"
        self._ipython_widget = None

        if self.instance.workspace.main_window.initialized:
            self.mainWindowInitializedEvent()

    @property
    def ipython_widget_available(self):
        return self._ipython_widget is not None

    def mainWindowInitializedEvent(self):
        self._init_widgets()
        self.reload()

    def reload(self):
        if self._ipython_widget is None:
            return

        import angr  # pylint: disable=import-outside-toplevel,multiple-imports
        import claripy
        import cle

        namespace = {
            "angr": angr,
            "claripy": claripy,
            "cle": cle,
            "workspace": self.instance.workspace,
            "instance": self.instance,
            "project": self.instance.project,
        }
        self._ipython_widget.push_namespace(namespace)

    def push_namespace(self, namespace):
        if self._ipython_widget is None:
            return

        self._ipython_widget.push_namespace(namespace)

    def print_text(self, msg):
        if self._ipython_widget is None:
            return

        self._ipython_widget.print_text(msg)

    def set_input_buffer(self, text):
        if self._ipython_widget is None:
            return
        self._ipython_widget.input_buffer = text

    @staticmethod
    def minimumSizeHint(*args, **kwargs):  # pylint: disable=unused-argument
        return QSize(0, 50)

    def _init_widgets(self):
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

    def command_executed(self, msg):
        if msg["msg_type"] == "execute_reply" and msg["content"]["status"] == "ok":
            view = self.instance.workspace.view_manager.first_view_in_category("disassembly")
            if view is not None:
                view.refresh()
