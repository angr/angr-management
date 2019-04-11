
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

FAKEFILE='/tmp/fake'

class InteractionView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('interaction', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Boo'

        self.rpipe, self.wpipe = os.pipe()

        with open(FAKEFILE, 'r') as f:
            os.write(self.wpipe, b'123')
        # self.rpipe.readline()


        self._function = None

        self._textedit = QCCodeEdit(self) # type:QCCodeEdit
        self._doc = None  # type:QCodeDocument
        self._highlighter = None  # type:QCCodeHighlighter
        self._options = None  # type:QDecompilationOptions
        self._message = []

        
        self._init_widgets()
        # self._buffer = QBuffer()
        # self._buffer.open(QIODevice.ReadWrite)


        self.servername = '/tmp/interaction'
       
        # for Connor
        self.server = QLocalServer(newConnection=self._connect_to_hacrs)
        self.server._listener = self._connect_to_hacrs
        self.server.listen(self.servername)
        
        self.client = QLocalSocket()
        self.client.connectToServer(self.servername)
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

        QObject.connect(self.hacrs_socket, SIGNAL('readyRead()'), self._hacrs_callback)
       

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


    def reload(self):
        if self.workspace.instance.project is None:
            return
        self._options.options = self._options.get_default_options()

    def decompile(self):

        if self._function is None:
            return

        d = self.workspace.instance.project.analyses.Decompiler(self._function,
                                                                cfg=self.workspace.instance.cfg,
                                                                optimization_passes=self._options.selected_options,
                                                                # kb=dec_kb
                                                                )
        self._doc = QCodeDocument(d.codegen)
        self._textedit.setDocument(self._doc)
        self._highlighter = QCCodeHighlighter(self._doc)

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

    def _on_cursor_position_changed(self):
        if self._doc is None:
            return

        cursor = self._textedit.textCursor()
        pos = cursor.position()
        selected_node = self._doc.get_node_at_position(pos)
        if selected_node is not None:
            # find all related text chunks and highlight them all
            chunks = self._doc.find_related_text_chunks(selected_node)
            # highlight these chunks
            self.highlight_chunks(chunks)
        else:
            self.highlight_chunks([ ])


    def _send_command(self):
        message = self._command.text()
        _l.info('sending message %s' % message)
        self._command.clear()
        
        self._hacrs.append(message)

        self.hacrs_socket.write(message.encode())
        _l.info('finish writing message %s' % message)
        # self._hacrs.append(message)
        # self._buffer.write(QByteArray(b'send'))
        # self._buffer.close()
        # mm = self._buffer.readAll()
        # self._buffer.write(QByteArray(message))
        # while self._buffer.waitForReadyRead(-1):
        #     _l.info('reading message')
        #     mm = self._buffer.readAll()
        #     self._hacrs.append(mm)

    def _display_new_messages(self):
        _l.info('display_new_message')
        while len(self._message) > 0:
            self._hacrs.append(self.pop(0))

    #
    # Private methods
    #

    def _init_widgets(self):
        
# GUI:
        self._hacrs = QTextEdit(self)
        self._command = QLineEdit(self)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("HaCRS"))
        layout.addWidget(self._hacrs)
        layout.addWidget(QLabel("Command"))
        layout.addWidget(self._command)
        # layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)
       
        self._command.returnPressed.connect(self._send_command)
        timer = QTimer()
        timer.timeout.connect(lambda _: _l.info('aaaaa'))
        # timer.timeout.connect(self._display_new_messages)
        timer.start(1000)
        
        from threading import Thread
        from time import sleep
        thread = Thread(target=self._display_new_messages, daemon=True)
        thread.start()

# Event handlers:
# def display_new_messages():
#     new_message = server.get(chat_url).text
#     if new_message:
#         text_area.append(new_message)
# 
# def send_message():
#     server.post(chat_url, {'name': name, 'message': message.text()})
#     message.clear()
# 
# from threading import Thread
# from time import sleep
# 
# new_messages = []
# def fetch_new_messages():
#     while True:
#         response = server.get(chat_url).text
#         if response:
#             new_messages.append(response)
#         sleep(.5)
# 
# thread = Thread(target=fetch_new_messages, daemon=True)
# thread.start()

        #####################
        # self.setLayout(QVBoxLayout())
        # button = QPushButton('Send')
        # textbox = QTextEdit()
        # self.layout().addWidget(textbox)
        # self.layout().addWidget(button)

        ##################
        # self._input = QTextEdit()
        # input_dock = QDockWidget('Command', self._input)
        # window.addDockWidget(Qt.LeftDockWidgetArea, input_dock)
       
       
        # self._output = QTextEdit(self)
        # output_dock = QDockWidget('Shell', self._output)
        # window.addDockWidget(Qt.RightDockWidgetArea, output_dock)
        # 
        # 
        # layout = QHBoxLayout()
        # layout.addWidget(window)
        # layout.setContentsMargins(0, 0, 0, 0)
        # self.setLayout(layout)


        # pseudo code text box
        # self._textedit = QCCodeEdit(self)
        # self._textedit.setTextInteractionFlags(Qt.TextSelectableByKeyboard | Qt.TextSelectableByMouse)
        # self._textedit.setLineWrapMode(QCCodeEdit.NoWrap)
        # textedit_dock = QDockWidget('Code', self._textedit)
        # window.setCentralWidget(textedit_dock)
        # textedit_dock.setWidget(self._textedit)

        # decompilation
        # self._options = QDecompilationOptions(self, self.workspace.instance, options=None)
        # options_dock = QDockWidget('Decompilation Options', self._options)
        # window.addDockWidget(Qt.RightDockWidgetArea, options_dock)
        # options_dock.setWidget(self._options)
