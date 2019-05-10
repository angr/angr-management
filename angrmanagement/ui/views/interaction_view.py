from PySide2.QtWidgets import QTextEdit, QVBoxLayout, QLabel, QWidget, QSplitter, QPushButton, QPlainTextEdit, \
    QMessageBox
from PySide2.QtGui import QFont
from PySide2.QtCore import Qt

import angr
try:
    import archr
    import keystone
    import nclib
except ImportError as e:
    archr = None
    keystone = None
    nclib = None

import socket

from .view import BaseView

from threading import Thread

import logging
_l = logging.getLogger(name=__name__)
_l.setLevel('DEBUG')


# TODO: on clicking interact multiple times, kill old the process, socket, and clean up
class InteractionView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('interaction', workspace, default_docking_position, *args, **kwargs)
        self.workspace = workspace

        self.caption = 'Interaction'

        self._history_text = None
        self._command = None
        self._init_widgets()

        self.sock = None

        self._msg_fmt = '%-10s: %s'

    #
    # Event callbacks
    #

    def _send_command(self):
        command = self._command.toPlainText()
        _l.debug('Sending command %s' % command)

        # GUI
        self._command.clear()

        self._history_text.append(self._msg_fmt % ('INPUT', command))

        if self.sock is not None:
            self.sock.write(command.encode())
        else:
            self._history_text.append('[ERROR] Connection not established. Did you load the image AND hit Interact (F6)?')

    def _init_widgets(self):

        # Subclass QPlainTextEdit
        class SmartPlainTextEdit(QPlainTextEdit):
            def __init__(self, parent, callback):
                super(SmartPlainTextEdit, self).__init__(parent)
                self._callback = callback
            def keyPressEvent(self, event):
                super(SmartPlainTextEdit, self).keyPressEvent(event)
                if event.key() == Qt.Key_Return:
                    if not (event.modifiers() == Qt.ShiftModifier):
                        self._callback()

        # Gui stuff
        splitter = QSplitter(self)

        output_wid = QWidget(splitter)
        output_wid.setLayout(QVBoxLayout(output_wid))
        self._history_text = QTextEdit(output_wid)
        self._history_text.setCurrentFont(QFont('Times', 10))
        self._history_text.setFontFamily('Source Code Pro')
        output_wid.layout().addWidget(QLabel("History"))
        output_wid.layout().addWidget(self._history_text)

        input_wid = QWidget(splitter)
        input_wid.setLayout(QVBoxLayout(input_wid))
        self._command = SmartPlainTextEdit(input_wid, self._send_command)
        input_wid.layout().addWidget(QLabel("Command"))
        input_wid.layout().addWidget(QLabel("Press Enter to send the command. Press Shift + Enter to add a newline."))
        input_wid.layout().addWidget(self._command)

        splitter.setOrientation(Qt.Vertical)
        splitter.addWidget(output_wid)
        splitter.addWidget(input_wid)
        splitter.setSizes([300,100])

        send_button = QPushButton(self, text="Send")
        clear_history_button = QPushButton(self, text="Clear History")
        interact_button = QPushButton(self, text="Interact")
        send_button.clicked.connect(self._send_command)
        clear_history_button.clicked.connect(self._history_text.clear)
        interact_button.clicked.connect(lambda: self.initialize(self.workspace.instance.img_name))
        buttons = QSplitter(self)
        buttons.addWidget(interact_button)
        buttons.addWidget(clear_history_button)
        buttons.addWidget(send_button)
        buttons.setSizes([100,200,600])

        self.setLayout(QVBoxLayout(self))
        self.layout().addWidget(splitter)
        self.layout().addWidget(buttons)

    def initialize(self, img_name):
        """
        This is an initialization for building up a connection between
        angr-management and archr
        """
        required = {
            'archr: git clone https://github.com/angr/archr && cd archr && pip install -e .':archr,
            'keystone: pip install --no-binary keystone-engine keystone-engine':keystone
            }
        is_missing = [ key for key, value in required.items() if value is None ]
        if len(is_missing) > 0:
            req_msg = 'To use this feature you need to install the following:\n\n\t' + '\n\t'.join(is_missing)
            req_msg += '\n\nInstall them to enable this functionality.'
            req_msg += '\nRelaunch angr-management after install.'
            QMessageBox(self).critical(None, 'Dependency error', req_msg)
            return

        if img_name is not None:
            _l.debug('Initializing the connection to archr with Image %s' % img_name)
            Thread(target=self.the_thread, args=(img_name,), daemon=True).start()

    def the_thread(self, img_name):
        with archr.targets.DockerImageTarget(img_name).build().start() as target:
            with target.flight_context() as flight:
                self.sock = flight.default_channel
                self._history_text.append('Connection established\n')
                while True:
                    try:
                        data = self.sock.recv()
                    except nclib.NetcatError:
                        break
                    else:
                        self._history_text.append(self._msg_fmt % ('OUTPUT', data.decode()))
                self._history_text.append('Connection closed')
                self.sock = None

    def setFocus(self):
        self._command.setFocus()
