
import logging
from PySide2.QtWidgets import QHBoxLayout, QPlainTextEdit, QDialog, QPushButton, QVBoxLayout
from PySide2.QtCore import QSize
import angr

from .view import BaseView

_l = logging.getLogger(name=__name__)


class TextEditLogger(logging.StreamHandler):
    def __init__(self, parent):
        super().__init__()
        self.widget = QPlainTextEdit(parent)
        self.widget.setReadOnly(True)

    def emit(self, record):
        msg = self.format(record)
        self.widget.appendPlainText(msg)

        super().emit(record)


class LoggingView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super(LoggingView, self).__init__('logging', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Logging'

        self.logger = TextEditLogger(self)

        self._init_widgets()


    def minimumSizeHint(self, *args, **kwargs):
        return QSize(0, 50)

    def dialogGenerator(self, parent=None):
        super().__init__(parent)
        logTextBox = self.textEditLogger(self)
        logTextBox.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(logTextBox)
        logging.getLogger().setLevel(logging.DEBUG)

        #testbutton
        self._button = QPushButton(self)
        self._button.setText('Test')

        #layout
        layout = QVBoxLayout()
        layout.addWidget(logTextBox.widget)
        self.setLayout(layout)

    def test(self):
        logging.debug('DEBUG: ')
        logging.info('INFO: ')
        logging.warning('WARNING ')
        logging.error('ERROR: ')

    def _init_widgets(self):
        angr.loggers.disable_root_logger()
        angr.loggers.handler = self.logger
        angr.loggers.enable_root_logger()

        hlayout = QHBoxLayout()
        hlayout.addWidget(self.logger.widget)
        self.setLayout(hlayout)
