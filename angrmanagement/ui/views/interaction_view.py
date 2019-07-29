import enum
import logging
from threading import Thread
from PySide2 import QtWidgets, QtCore

from .view import BaseView

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


_l = logging.getLogger(name=__name__)


# not a namedtuple so it can be mutable. I think this is not a terrible idea.
class SavedInteraction:
    def __init__(self, name, protocol, log):
        self.name = name
        self.protocol = protocol
        self.log = log


class ProtocolInteractor:
    def __init__(self, view, sock):
        self.view = view  # type: InteractionView
        self.sock = sock  # type: nclib.Netcat

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

class InteractionState(enum.Enum):
    BEGINNING = 1
    RUNNING = 2
    STOPPED = 3
    VIEWING = 4

class InteractionView(BaseView):
    def __init__(self, workspace, *args, **kwargs):
        super().__init__('interaction', workspace, *args, **kwargs)
        self.caption = 'Interaction'
        self.current_log = []  # for now each entry is a dict. each entry has {"dir": "in"/"out", "data": bytes} and then whatever
                       # "in" here means it's input to the program
        self.log_controls = []
        self.sock = None  # type: nclib.Netcat

        self._state = None

        self.widget_button_start = None
        self.widget_button_stop = None
        self.widget_combobox_protocol = None
        self.widget_area_log = None
        self.widget_input = None
        self.widget_text_savename = None

        self.widget_group_start = None
        self.widget_group_running = None
        self.widget_group_save = None
        self.widget_group_load = None

        self.running_protocol = None  # type: ProtocolInteractor
        self.chosen_protocol = None  # type: type

        self._init_widgets()
        self._state_transition(InteractionState.BEGINNING)

        self._signal_start.connect(self._handler_start)
        self._signal_data.connect(self._handler_data)
        self._signal_eof.connect(self._handler_eof)

    _signal_start = QtCore.Signal()
    _signal_data = QtCore.Signal(bytes)
    _signal_eof = QtCore.Signal()

    @property
    def selected_protocol(self):
        return self.workspace.instance.interaction_protocols[self.widget_combobox_protocol.currentIndex()]

    # log_add/clear will be called by the base class. it's the subclass' responsibility to call input_show and
    # input_hide depending on whether or not the protocol is accepting input

    def log_add(self, model):
        self.current_log.append(model)
        control = self.running_protocol.render_log_entry(model)
        control.setParent(self.widget_area_log)
        self.widget_area_log.layout().insertWidget(len(self.log_controls), control)
        self.log_controls.append(control)

    def log_clear(self):
        for control in self.log_controls:
            self.widget_area_log.layout().removeWidget(control)
            control.deleteLater()
        self.log_controls = []
        self.current_log = []

    def input_show(self):
        if self.running_protocol is None:
            self.input_hide()
            return

        new_widget = self.running_protocol.render_input_form()
        if new_widget is None:
            return
        if self.widget_input is not None:
            self.input_hide()
        new_widget.setParent(self.widget_area_log)
        self.widget_area_log.layout().insertWidget(len(self.log_controls), new_widget)
        self.widget_input = new_widget

    def input_hide(self):
        if self.widget_input is None:
            return
        self.widget_area_log.layout().removeWidget(self.widget_input)
        self.widget_input.deleteLater()
        self.widget_input = None

    # events from the thread

    def _handler_start(self):
        self.running_protocol.consume_start()

    def _handler_data(self, data):
        self.running_protocol.consume_data(data)

    def _handler_eof(self):
        self.running_protocol.consume_eof()
        self._state_transition(InteractionState.STOPPED)

    # data model events

    def _handler_update_interactions(self, **kwargs):
        while self.widget_combobox_load.count():
            self.widget_combobox_load.removeItem(0)
        for interaction in self.workspace.instance.interactions:
            self.widget_combobox_load.addItem(interaction.name)

    def _handler_update_protocols(self, **kwargs):
        while self.widget_combobox_protocol.count():
            self.widget_combobox_protocol.removeItem(0)
        for protocol in self.workspace.instance.interaction_protocols:
            self.widget_combobox_protocol.addItem(protocol.__name__)

    # utility for tweaking the control panel

    def _state_transition(self, state):
        self._state = state
        if state == InteractionState.BEGINNING:
            self.widget_group_start.setHidden(False)
            self.widget_group_running.setHidden(True)
            self.widget_group_save.setHidden(True)
            self.widget_group_load.setHidden(False)
            self.input_hide()
            self.log_clear()
        elif state == InteractionState.RUNNING:
            self.widget_group_start.setHidden(True)
            self.widget_group_running.setHidden(False)
            self.widget_group_save.setHidden(True)
            self.widget_group_load.setHidden(True)
            self.log_clear()
        elif state == InteractionState.STOPPED:
            self.widget_group_start.setHidden(False)
            self.widget_group_running.setHidden(True)
            self.widget_group_save.setHidden(False)
            self.widget_group_load.setHidden(False)
            self.input_hide()
            self.running_protocol = None
        elif state == InteractionState.VIEWING:
            self.widget_group_start.setHidden(False)
            self.widget_group_running.setHidden(True)
            self.widget_group_save.setHidden(True)
            self.widget_group_load.setHidden(False)
            self.input_hide()
            self.log_clear()
        else:
            raise ValueError(state)

    # buttons

    def _save_interaction(self):
        self.workspace.instance.interactions.am_obj.append(SavedInteraction(self.widget_text_savename.text(), self.chosen_protocol, self.current_log))
        self.workspace.instance.interactions.am_event()

    def _load_interaction(self):
        if self.widget_combobox_load.currentIndex() == -1:
            return
        thing = self.workspace.instance.interactions[self.widget_combobox_load.currentIndex()]
        self.chosen_protocol = thing.protocol
        self.running_protocol = self.chosen_protocol(self, None)  # does this mean the abstractions are fucked?
        self._state_transition(InteractionState.VIEWING)
        for model in thing.log:
            self.log_add(model)

    def _abort_interaction(self):
        self.running_protocol.sock.close()
        self._state_transition(InteractionState.STOPPED)

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
            QtWidgets.QMessageBox.critical(None, 'Dependency error', req_msg)
            return

        img_name = self.workspace.instance.img_name
        if img_name is None:
            QtWidgets.QMessageBox.critical(None, 'Nothing to run', "The project was not loaded from a docker image")
            return

        _l.debug('Initializing the connection to archr with image %s' % img_name)
        self._state_transition(InteractionState.RUNNING)
        Thread(target=self._socket_thread, args=(img_name,), daemon=True).start()

    def _socket_thread(self, img_name):
        with archr.targets.DockerImageTarget(img_name).build().start() as target:
            with target.flight_context() as flight:
                sock = flight.default_channel
                sock._raise_timeout = True
                self.chosen_protocol = self.selected_protocol
                self.running_protocol = self.chosen_protocol(self, sock)
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

        box_start = QtWidgets.QGroupBox(leftBox)
        box_start.setLayout(QtWidgets.QVBoxLayout(box_start))
        box_start.setTitle("New Interaction")
        leftBox.layout().addWidget(box_start)
        self.widget_group_start = box_start

        box_running = QtWidgets.QGroupBox(leftBox)
        box_running.setLayout(QtWidgets.QVBoxLayout(box_running))
        box_running.setTitle("Interaction Control")
        leftBox.layout().addWidget(box_running)
        self.widget_group_running = box_running

        box_save = QtWidgets.QGroupBox(leftBox)
        box_save.setLayout(QtWidgets.QVBoxLayout(box_save))
        box_save.setTitle("Save Interaction")
        leftBox.layout().addWidget(box_save)
        self.widget_group_save = box_save

        box_load = QtWidgets.QGroupBox(leftBox)
        box_load.setLayout(QtWidgets.QVBoxLayout(box_load))
        box_load.setTitle("Load Interaction")
        leftBox.layout().addWidget(box_load)
        self.widget_group_load = box_load

        leftBox.layout().addStretch(0)

        protocolBox = QtWidgets.QComboBox(box_start)
        box_start.layout().addWidget(protocolBox)
        self.widget_combobox_protocol = protocolBox
        self.workspace.instance.interaction_protocols.am_subscribe(self._handler_update_protocols)
        self._handler_update_protocols()

        start_button = QtWidgets.QPushButton(box_start)
        start_button.setText("Connect")
        start_button.clicked.connect(self._start_interaction)
        box_start.layout().addWidget(start_button)
        self.widget_button_start = start_button

        stop_button = QtWidgets.QPushButton(box_running)
        stop_button.setText("Abort Interaction")
        stop_button.clicked.connect(self._abort_interaction)
        box_running.layout().addWidget(stop_button)
        self.widget_button_stop = stop_button

        save_text = QtWidgets.QLineEdit(box_save)
        save_text.setText("my_interaction")
        save_text.setPlaceholderText("Interaction Name")
        save_text.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Ignored, QtWidgets.QSizePolicy.Fixed))
        box_save.layout().addWidget(save_text)
        self.widget_text_savename = save_text

        load_picker = QtWidgets.QComboBox(box_load)
        box_load.layout().addWidget(load_picker)
        self.widget_combobox_load = load_picker
        self.workspace.instance.interactions.am_subscribe(self._handler_update_interactions)
        self._handler_update_interactions()

        load_button = QtWidgets.QPushButton(box_load)
        load_button.setText("Load")
        load_button.clicked.connect(self._load_interaction)
        box_load.layout().addWidget(load_button)

        save_button = QtWidgets.QPushButton(box_save)
        save_button.setText("Save")
        box_save.layout().addWidget(save_button)
        save_button.clicked.connect(self._save_interaction)

        scrollArea = QtWidgets.QScrollArea(self)
        scrollArea.setWidgetResizable(True)
        self.layout().addWidget(scrollArea)

        scrollAreaWidgetContents = QtWidgets.QWidget(scrollArea)
        scrollAreaWidgetContents.setLayout(QtWidgets.QVBoxLayout(scrollAreaWidgetContents))
        scrollArea.setWidget(scrollAreaWidgetContents)

        self.widget_area_log = scrollAreaWidgetContents
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
        if self.view.widget_input is not None:
            cur_input = self.view.widget_input.toPlainText()
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
        data_bytes = self.view.widget_input.toPlainText().encode('latin-1')
        self.sock.send(data_bytes)
        self.view.log_add({"dir": "in", "data": data_bytes})
        self.view.widget_input.setPlainText('')
