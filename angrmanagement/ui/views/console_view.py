
import logging
from PySide2.QtWidgets import QHBoxLayout
from PySide2.QtCore import QSize
from traitlets.config.configurable import MultipleInstanceError

from .view import BaseView

_l = logging.getLogger(name=__name__)


class ConsoleView(BaseView):
    """
    Console view providing IPython interactive session.
    """

    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('console', workspace, default_docking_position, *args, **kwargs)

        self.base_caption = 'Console'
        self._ipython_widget = None

        self._init_widgets()
        self.reload()

    @property
    def ipython_widget_available(self):
        return self._ipython_widget is not None

    def reload(self):

        if self._ipython_widget is None:
            return

        import angr, claripy, cle # pylint: disable=import-outside-toplevel,multiple-imports

        namespace = {'angr': angr,
                     'claripy': claripy,
                     'cle': cle,
                     'workspace': self.workspace,
                     'instance': self.workspace.instance,
                     'project': self.workspace.instance.project,
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
    def minimumSizeHint(*args, **kwargs): # pylint: disable=unused-argument
        return QSize(0, 50)

    def _init_widgets(self):

        import angr, claripy, cle # pylint: disable=import-outside-toplevel,multiple-imports

        namespace = {
            'angr': angr,
            'claripy': claripy,
            'cle': cle,
        }

        from ..widgets.qipython_widget import QIPythonWidget  # pylint:disable=import-outside-toplevel
        try:
            ipython_widget = QIPythonWidget(namespace=namespace)
        except MultipleInstanceError:
            _l.warning("Fails to load the Console view since an IPython interpreter has already been loaded. "
                       "You might be running angr Management with IPython.")
            return

        self._ipython_widget = ipython_widget
        ipython_widget.executed.connect(self.command_executed)

        hlayout = QHBoxLayout()
        hlayout.addWidget(ipython_widget)

        self.setLayout(hlayout)

    def command_executed(self,msg):
        if msg["msg_type"] == "execute_reply" and msg["content"]["status"] == "ok":
            view = self.workspace.view_manager.first_view_in_category("disassembly")
            if view is not None:
                view.refresh()
