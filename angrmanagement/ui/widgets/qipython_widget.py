from IPython.lib import guisupport
from qtconsole.inprocess import QtInProcessKernelManager
from qtconsole.rich_jupyter_widget import RichJupyterWidget

from angrmanagement.ui.css import CSS


class QIPythonWidget(RichJupyterWidget):
    def __init__(self, *args, banner=None, namespace=None, **kwargs):
        if banner is not None:
            self.banner = banner
        RichJupyterWidget.__init__(self, *args, **kwargs)
        self._on_css_updated()
        CSS.global_css.am_subscribe(self._on_css_updated)

        self.kernel_manager = kernel_manager = QtInProcessKernelManager()
        kernel_manager.start_kernel()
        kernel_manager.kernel.gui = "qt4"

        if namespace is not None:
            self.push_namespace(namespace)

        self.kernel_client = kernel_client = self._kernel_manager.client()
        kernel_client.start_channels()

        def stop():
            kernel_client.stop_channels()
            kernel_manager.shutdown_kernel()
            guisupport.get_app_qt4().exit()

        self.exit_requested.connect(stop)

        self.enable_calltips = False

    def __del__(self):
        super().__del__()
        CSS.global_css.am_unsubscribe(self._on_css_updated)

    def _on_css_updated(self):
        self.setStyleSheet(CSS.global_css.am_obj)

    def push_namespace(self, namespace):
        self.kernel_manager.kernel.shell.push(namespace)

    def clear_terminal(self):
        self._control.clear()

    def print_text(self, text):
        self._append_plain_text(text, True)

    def execute_command(self, command):
        self._execute(command, False)
