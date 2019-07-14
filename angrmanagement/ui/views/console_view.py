
import logging
from PySide2.QtWidgets import QHBoxLayout
from PySide2.QtCore import QSize
from traitlets.config.configurable import MultipleInstanceError

from .view import BaseView
from ..widgets.qipython_widget import QIPythonWidget

_l = logging.getLogger(name=__name__)


class ConsoleView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super(ConsoleView, self).__init__('console', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Console'
        self._ipython_widget = None

        self._init_widgets()

    def reload(self):

        if self._ipython_widget is None:
            return

        import angr, claripy, cle

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

    def minimumSizeHint(self, *args, **kwargs):
        return QSize(0, 50)

    def _init_widgets(self):

        import angr, claripy, cle

        namespace = {
            'angr': angr,
            'claripy': claripy,
            'cle': cle,
        }

        try:
            ipython_widget = QIPythonWidget(namespace=namespace)
        except MultipleInstanceError:
            _l.warning("Fails to load the Console view since an IPython interpreter has already been loaded. "
                       "You might be running angr Management with IPython.")
            return

        self._ipython_widget = ipython_widget

        hlayout = QHBoxLayout()
        hlayout.addWidget(ipython_widget)

        self.setLayout(hlayout)
