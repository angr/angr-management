
from PySide.QtGui import QFrame, QHBoxLayout, QLabel

class QDisasmStatusBar(QFrame):
    def __init__(self, parent=None):
        super(QDisasmStatusBar, self).__init__(parent)

        # widgets
        self._function_label = None  # type: QLabel

        # information
        self._function = None

        self._init_widgets()

    @property
    def function(self):
        return self._function

    @function.setter
    def function(self, f):
        self._function = f

        self._update_function_address()

    @property
    def function_address(self):
        if self._function is None:
            return None
        return self._function.addr

    #
    # Initialization
    #

    def _init_widgets(self):

        # current function
        function_label = QLabel()
        self._function_label = function_label

        layout = QHBoxLayout()
        layout.setContentsMargins(2, 2, 2, 2)
        layout.addWidget(function_label)

        self.setLayout(layout)

    #
    # Private methods
    #

    def _update_function_address(self):
        if self.function_address is not None:
            self._function_label.setText("Function %x" % self.function_address)
