from PySide2.QtWidgets import QTextEdit, QVBoxLayout, QLineEdit, QLabel, QMessageBox
from PySide2.QtGui import QFont
from PySide2.QtCore import Qt, QObject, SIGNAL, QMutex
from PySide2.QtNetwork import QLocalServer, QLocalSocket

import angr

import socket
import nclib

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

        self._hacrs = None
        self._command = None
        self._init_widgets()

        self.sock = None

        self._msg_fmt = '%-10s: %s'

    #
    # Event callbacks
    #

    def _send_command(self):
        command = self._command.text()
        _l.debug('Sending command %s' % command)

        # GUI
        self._command.clear()

        self._hacrs.append(self._msg_fmt % ('INPUT', command))

        if self.sock is not None:
            self.sock.write(command.encode())
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
        Thread(target=self.the_thread, args=(img_name,)).start()

    def the_thread(self, img_name):
        with archr.targets.DockerImageTarget(img_name).build().start() as target:
            with target.flight_context() as flight:
                self.sock = flight.default_channel
                self._hacrs.append('Connection established\n')
                while True:
                    try:
                        data = self.sock.recv()
                    except nclib.NetcatError:
                        break
                    else:
                        self._hacrs.append(self._msg_fmt % ('OUTPUT', data.decode()))
                self._hacrs.append('Connection closed')
                self.sock = None

    def setFocus(self):
        self._command.setFocus()
