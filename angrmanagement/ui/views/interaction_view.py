from PySide2.QtWidgets import QTextEdit, QVBoxLayout, QLineEdit, QLabel, QMessageBox
from PySide2.QtGui import QFont
from PySide2.QtCore import Qt, QObject, SIGNAL, QMutex
from PySide2.QtNetwork import QLocalServer, QLocalSocket

import angr

import socket

from .view import BaseView

import os, contextlib, subprocess
from threading import Thread

import logging
_l = logging.getLogger(name=__name__)
_l.setLevel('DEBUG')

class InteractionView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('interaction', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Interaction'
        self.img_name = None
        self._servername = '/tmp/interaction'
        # TODO: take rid of this hack
        if os.path.exists(self._servername):
            os.remove(self._servername)

        self._hacrs = None
        self._command = None
        self._init_widgets()

        self._server = None
        self._server_socket = None
        self._client_socket = None

        self._mutex = QMutex()

        self._msg_fmt = '%-10s: %s'

    def _new_connect(self):
        self._server_socket = self._server.nextPendingConnection()
        thread = Thread(target=self._call_archr, args=(self.img_name,), daemon=True)
        thread.start()

    def _call_archr(self, img_name):
        _l.debug('Calling Archr with image %s' % img_name)
        try:
            import archr
        except ImportError:
            QMessageBox(self).critical(None, 'Import error', 'Please make sure archr is installed.')
        target = archr.targets.DockerImageTarget(img_name).build()
        with contextlib.suppress(subprocess.TimeoutExpired), target.start():
            bow = archr.arsenal.ContextBow(target)
            import nclib
            in_socket = socket.fromfd(self._server_socket.socketDescriptor(), socket.AF_INET, socket.SOCK_STREAM)
            nc_in_sock = nclib.netcat.Netcat(sock=in_socket)
            out_socket = socket.fromfd(self._client_socket.socketDescriptor(), socket.AF_INET, socket.SOCK_STREAM)
            nc_out_sock = nclib.netcat.Netcat(sock=out_socket)
            # arrowhead = archr.arrowheads.ArrowheadFletcher(self._server_socket.socketDescriptor(), self._client_socket.socketDescriptor())
            arrowhead = archr.arrowheads.ArrowheadFletcher(nc_in_sock, nc_out_sock)
            flight = bow.fire(testcase=arrowhead)
    
    def _callback(self):
        self._mutex.lock()
        # TODO: This is another hack
        msg = self._client_socket.read(2048)
        _l.debug('Receiving Message %s' % str(msg))
        self._hacrs.append(self._msg_fmt % ('OUTPUT', str(msg.data(), encoding='utf-8')))
        self._mutex.unlock()

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
        _l.debug('Sending command %s' % command)

        # GUI
        self._command.clear()

        self._hacrs.append(self._msg_fmt % ('INPUT', command))

        if self._server_socket is not None:
            self._server_socket.write(command.encode())
        else:
            self._hacrs.append('[ERROR] Connection not established. Did you load the image AND hit Interact (F6)?')
    
    def _init_widgets(self):
        self._hacrs = QTextEdit(self)
        # TODO: inherit from a formatted QTextEdit class
        self._hacrs.setCurrentFont(QFont('Times', 10))
        self._hacrs.setFontFamily('Source Code Pro')
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
       
    def initialize(self, img_name):
        """
        This is an initialization for building up a connection between
        angr-management and archr
        """
        _l.debug('Initializing the connection to archr with Image %s' % img_name)

        self.img_name = img_name

        self._server = QLocalServer(newConnection=self._new_connect)
        self._server.listen(self._servername)

        self._client_socket = QLocalSocket()
        self._client_socket.connectToServer(self._servername)

        QObject.connect(self._client_socket, SIGNAL('readyRead()'), self._callback)

    def setFocus(self):
        self._command.setFocus()
