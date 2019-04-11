
from PySide2.QtWidgets import QHBoxLayout, QTextEdit, QMainWindow, QDockWidget, QVBoxLayout, QPushButton, QLineEdit, QLabel
from PySide2.QtGui import QTextCursor, QTextDocument
from PySide2.QtCore import Qt, QBuffer, QIODevice, QTimer, QByteArray, QObject, SIGNAL

from PySide2.QtNetwork import QLocalServer, QLocalSocket

import angr

from ..widgets.qccode_edit import QCCodeEdit
from ..widgets.qccode_highlighter import QCCodeHighlighter
from ..widgets.qdecomp_options import QDecompilationOptions
from ..documents import QCodeDocument
from .view import BaseView

import os
import logging
import time
from threading import Thread
_l = logging.getLogger(name=__name__)
_l.setLevel('INFO')


class InteractionView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('interaction', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'HaCRS'

        # self._function = None

        # self._textedit = QCCodeEdit(self) # type:QCCodeEdit
        # self._doc = None  # type:QCodeDocument
        # self._highlighter = None  # type:QCCodeHighlighter
        
        self._init_widgets()


        self._servername = '/tmp/interaction'
       
        # for Connor
        self.server = QLocalServer(newConnection=self._connect_to_hacrs)
        # self.server._listener = self._connect_to_hacrs
        self.server.listen(self._servername)
        
        self.client = QLocalSocket()
        self.client.connectToServer(self._servername)
        QObject.connect(self.client, SIGNAL('readyRead()'), self._callback)
        time.sleep(5)
        self.client.write(b'abc')


    def _connect_to_hacrs(self):
        _l.info('connect_to_hacrs')
        self.hacrs_socket = self.server.nextPendingConnection()
        if hasattr(self.workspace.instance, 'img_name'):
            img_name = self.workspace.instance.img_name
        else:
            img_name = 'cat'

        thread = Thread(target=self._call_archr, args=(img_name,), daemon=True)
        thread.start()

    def _call_archr(self, img_name):
        import archr, contextlib, subprocess
        _l.info('Calling Archr')
        target = archr.targets.DockerImageTarget(img_name).build()
        with contextlib.suppress(subprocess.TimeoutExpired), target.start():
            bow = archr.arsenal.ContextBow(target)
            arrowhead = archr.arrowheads.ArrowheadFletcher(self.hacrs_socket, self.client)
            flight = bow.fire(testcase=arrowhead)
    
    def _hacrs_callback(self):
        # TODO: MAGIC
        pass
        # cmd = self.hacrs_socket.read(2048).data()
        # Call Hacrs with seslf.hacrs_socket
        # self.hacrs_socket.write(b'aa')

    def _callback(self):
	# self.tiffany_mutex.lock() # Make sure this blocking
        _l.info('client read')
        msg = self.client.read(2048)
        _l.info(msg)
        self._hacrs.append(msg.data().decode())
	# self.tiffany_mutex.unlock()


    def setFocus(self):
        self._textedit.setFocus()

    #
    # Properties
    #

    @property
    def function(self):
        return self._function

    @function.setter
    def function(self, v):
        if v is self._function:
            return
        self._function = v
        self.decompile()


    #
    # Event callbacks
    #

    def _send_command(self):
        command = self._command.text()
        _l.info('Sending command %s' % command)

        # GUI
        self._command.clear()
        self._hacrs.append(command)

        self.hacrs_socket.write(command.encode())
    
    def _init_widgets(self):
        self._hacrs = QTextEdit(self)
        self._command = QLineEdit(self)
        self._command.returnPressed.connect(self._send_command)
        
        # GUI:
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("HaCRS"))
        layout.addWidget(self._hacrs)
        layout.addWidget(QLabel("Command"))
        layout.addWidget(self._command)
        # layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)
       

