
from PySide.QtGui import QHBoxLayout
from PySide.QtCore import QSize

from .view import BaseView
from ..widgets.qipython_widget import QIPythonWidget


class ConsoleView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super(ConsoleView, self).__init__('console', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Console'
        self._ipython_widget = None

        self._init_widgets()

    def reload(self):

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
        self._ipython_widget.push_namespace(namespace)

    def sizeHint(self):
        return QSize(400, 50)

    def _init_widgets(self):

        import angr, claripy, cle

        namespace = {
            'angr': angr,
            'claripy': claripy,
            'cle': cle,
        }

        ipython_widget = QIPythonWidget(namespace=namespace)
        self._ipython_widget = ipython_widget

        hlayout = QHBoxLayout()
        hlayout.addWidget(ipython_widget)

        self.setLayout(hlayout)
