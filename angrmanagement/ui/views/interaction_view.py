from PySide2 import QtWidgets, QtCore

try:
    import nclib
except ImportError:
    nclib = None
try:
    import keystone
except ImportError:
    keystone = None
try:
    import archr
except ImportError:
    archr = None

from .view import BaseView

from threading import Thread

import logging
_l = logging.getLogger(name=__name__)
_l.setLevel('DEBUG')


class ProtocolInteractor:
    def __init__(self, view, sock):
        self.view = view
        self.sock = sock

    def consume_data(self, data):
        # try to decode it
        # add it to the log, perhaps mutating the last entry if an entire entity wasn't received (no support yet)
        raise NotImplementedError

    def consume_start(self):
        raise NotImplementedError

    def consume_eof(self):
        raise NotImplementedError

    def render_input_form(self):
        # determine what the current input control should look like. returns a QWidget.
        # if there's already partially written input, translate it to the new form if possible
        raise NotImplementedError

    def render_log_entry(self, model):
        # render a model from the log into a QWidget
        raise NotImplementedError


class InteractionView(BaseView):
    # has logic for rendering a form and serializing/deserializing a packet to it
    def __init__(self, workspace, *args, **kwargs):
        super().__init__('interaction', workspace, *args, **kwargs)
        self.caption = 'Interaction'
        self.log = []  # for now each entry is a dict. each entry has {"dir": "in"/"out", "data": bytes} and then whatever
                       # "in" here means it's input to the program
        self.log_controls = []
        self.sock = None  # type: nclib.Netcat

        self.start_button = None
        self.stop_button = None
        self.log_area = None
        self.input_widget = None
        self.protocol_widget = None
        self.running_protocol = None  # type: ProtocolInteractor
        self.protocols = [PlainTextProtocol]

        self._init_widgets()

        self._signal_start.connect(self._handler_start)
        self._signal_data.connect(self._handler_data)
        self._signal_eof.connect(self._handler_eof)

    _signal_start = QtCore.Signal()
    _signal_data = QtCore.Signal(bytes)
    _signal_eof = QtCore.Signal()

    @property
    def selected_protocol(self):
        return self.protocols[self.protocol_widget.currentIndex()]

    # log_add/clear will be called by the base class. it's the subclass' responsibility to call input_show and
    # input_hide depending on whether or not the protocol is accepting input

    def log_add(self, model):
        self.log.append(model)
        control = self.running_protocol.render_log_entry(model)
        control.setParent(self.log_area)
        self.log_area.layout().insertWidget(len(self.log_controls), control)
        self.log_controls.append(control)

    def log_clear(self):
        for control in self.log_controls:
            self.log_area.layout().removeWidget(control)
            control.deleteLater()
        self.log_controls = []

    def input_show(self):
        if self.running_protocol is None:
            self.input_hide()
            return

        new_widget = self.running_protocol.render_input_form()
        if new_widget is None:
            return
        if self.input_widget is not None:
            self.input_hide()
        new_widget.setParent(self.log_area)
        self.log_area.layout().insertWidget(len(self.log_controls), new_widget)
        self.input_widget = new_widget

    def input_hide(self):
        if self.input_widget is None:
            return
        self.log_area.layout().removeWidget(self.input_widget)
        self.input_widget.deleteLater()
        self.input_widget = None

    # events from the thread

    def _handler_start(self):
        self.log_clear()
        self.running_protocol.consume_start()

    def _handler_data(self, data):
        self.running_protocol.consume_data(data)

    def _handler_eof(self):
        self.running_protocol.consume_eof()
        self.running_protocol = None
        self._toggle_buttons(started=False)
        self.input_hide()

    # utility for tweaking the control panel

    def _toggle_buttons(self, started):
        self.stop_button.setHidden(not started)
        self.start_button.setHidden(started)

    # buttons

    def _abort_interaction(self):
        self.running_protocol.sock.close()
        self.running_protocol = None
        self._toggle_buttons(started=False)
        self.input_hide()

    def _start_interaction(self):
        required = {
            'archr: git clone https://github.com/angr/archr && cd archr && pip install -e .':archr,
            'keystone: pip install --no-binary keystone-engine keystone-engine':keystone
        }
        is_missing = [ key for key, value in required.items() if value is None ]
        if len(is_missing) > 0:
            req_msg = 'To use this feature you need to install the following:\n\n\t' + '\n\t'.join(is_missing)
            req_msg += '\n\nInstall them to enable this functionality.'
            req_msg += '\nRelaunch angr-management after install.'
            QtWidgets.QMessageBox(self).critical(None, 'Dependency error', req_msg)
            return

        img_name = self.workspace.instance.img_name
        if img_name is None:
            QtWidgets.QMessageBox(self).critical(None, 'Nothing to run', "The project was not loaded from a docker image")
            return

        _l.debug('Initializing the connection to archr with image %s' % img_name)
        self.log_clear()
        self._toggle_buttons(started=True)
        Thread(target=self._socket_thread, args=(img_name,), daemon=True).start()

    def _socket_thread(self, img_name):
        with archr.targets.DockerImageTarget(img_name).build().start() as target:
            with target.flight_context() as flight:
                sock = flight.default_channel
                sock._raise_timeout = True
                self.running_protocol = self.selected_protocol(self, sock)
                _l.debug("Connected to running target")
                self._signal_start.emit()
                while self.running_protocol is not None:
                    try:
                        data = sock.recv(timeout=1)
                    except nclib.NetcatTimeout:
                        continue
                    except nclib.NetcatError:
                        break
                    if not data:
                        break
                    self._signal_data.emit(data)

                if self.running_protocol is not None:
                    _l.debug("Connection dropped by server")
                    self._signal_eof.emit()
                else:
                    _l.debug("Connection closed by client")

    def _init_widgets(self):
        self.setLayout(QtWidgets.QHBoxLayout(self))

        leftBox = QtWidgets.QWidget(self)
        leftBox.setLayout(QtWidgets.QVBoxLayout(leftBox))
        self.layout().addWidget(leftBox)

        groupBox = QtWidgets.QGroupBox(leftBox)
        groupBox.setLayout(QtWidgets.QVBoxLayout(groupBox))
        groupBox.setTitle("Interaction Controls")
        leftBox.layout().addWidget(groupBox)
        leftBox.layout().addStretch(0)

        protocolBox = QtWidgets.QComboBox(groupBox)
        for protocol in self.protocols:
            protocolBox.addItem(protocol.__name__)
        groupBox.layout().addWidget(protocolBox)
        self.protocol_widget = protocolBox

        start_button = QtWidgets.QPushButton(groupBox)
        start_button.setText("Start Interaction")
        start_button.clicked.connect(self._start_interaction)
        groupBox.layout().addWidget(start_button)
        self.start_button = start_button

        stop_button = QtWidgets.QPushButton(groupBox)
        stop_button.setHidden(True)
        stop_button.setText("Abort Interaction")
        stop_button.clicked.connect(self._abort_interaction)
        groupBox.layout().addWidget(stop_button)
        self.stop_button = stop_button

        scrollArea = QtWidgets.QScrollArea(self)
        scrollArea.setWidgetResizable(True)
        self.layout().addWidget(scrollArea)

        scrollAreaWidgetContents = QtWidgets.QWidget(scrollArea)
        scrollAreaWidgetContents.setLayout(QtWidgets.QVBoxLayout(scrollAreaWidgetContents))
        scrollArea.setWidget(scrollAreaWidgetContents)

        self.log_area = scrollAreaWidgetContents
        scrollAreaWidgetContents.layout().addStretch(0)


# Subclass QPlainTextEdit
class SmartPlainTextEdit(QtWidgets.QPlainTextEdit):
    def __init__(self, parent, callback):
        super(SmartPlainTextEdit, self).__init__(parent)
        self._callback = callback

    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key_Return:
            if event.modifiers() != QtCore.Qt.ShiftModifier:
                self._callback()
                return
        super(SmartPlainTextEdit, self).keyPressEvent(event)


class PlainTextProtocol(ProtocolInteractor):
    def consume_start(self):
        # set whatever state related to the beginning of the protocol
        # here, we mark that we can accept user input
        self.view.input_show()

    def consume_data(self, data):
        # process the consumption of data coming off the wire
        # should deserialize it into whatever form you want and then add it to the log
        self.view.log_add({"dir": "out", "data": data})

    def consume_eof(self):
        # tweak anything you care about on eof
        pass

    def render_input_form(self):
        # will be called whenever we need to show the input form
        # should translate any data we need between the old and new forms
        if self.view.input_widget is not None:
            cur_input = self.view.input_widget.toPlainText()
        else:
            cur_input = ''
        txt = SmartPlainTextEdit(None, self._send_callback)
        txt.setPlainText(cur_input)
        return txt

    def render_log_entry(self, model):
        # will be called to render the entries added to the log
        txt = QtWidgets.QLabel()
        txt.setText(model['data'].decode('latin-1'))
        return txt

    def _send_callback(self):
        data_bytes = self.view.input_widget.toPlainText().encode('latin-1')
        self.sock.send(data_bytes)
        self.view.log_add({"dir": "in", "data": data_bytes})
        self.view.input_widget.setPlainText('')

