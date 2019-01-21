from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, \
    QGridLayout, QComboBox, \
    QLineEdit, QTextEdit, QTreeWidget, QTreeWidgetItem
from PySide2.QtCore import Qt
import angr

from ..widgets import QAddressInput, QStateComboBox
from ...utils.namegen import NameGenerator


class StateMetadata(angr.SimStatePlugin):
    def __init__(self):
        super(StateMetadata, self).__init__()
        self.name = None                # the state's name
        self.base_name = None           # the name of the base state this was created from
        self.is_original = False         # is this the original instanciation of this name?
        self.is_base = False             # is this state created with nothing else as a base?

    def copy(self, memo=None):
        c = StateMetadata()
        c.name = self.name
        c.base_name = self.base_name
        c.is_original = False
        c.is_base = False
        return c


StateMetadata.register_default('gui_data')


def is_option(o):
    for ch in o:
        if ch not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_':
            return False
    return True


class NewState(QDialog):
    def __init__(self, instance, addr=None, create_simgr=False, parent=None):
        super(NewState, self).__init__(parent)

        # initialization

        self.instance = instance
        self.state = None  # output

        self._options = set()
        self._addr = addr
        self._create_simgr = create_simgr  # Shall we create a new simgr after clicking OK?

        self._name_edit = None  # type: QLineEdit
        self._base_state_combo = None  # type: QStateComboBox
        self._mode_combo = None  # type: QComboBox
        self._editor = None  # type: QTextEdit
        self._ok_button = None

        self.setWindowTitle('New State')

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def _init_widgets(self):
        layout = QGridLayout()
        row = 0

        validation_failures = set()

        # name

        name_label = QLabel(self)
        name_label.setText("Name")

        name_box = QLineEdit(self)
        name_box.setText(NameGenerator.random_name())

        def handle_name(txt):
            nonlocal validation_failures
            key = {'name'}
            if txt and not any(s.gui_data.name == txt for s in self.instance.states):
                validation_failures -= key
            else:
                validation_failures |= key
            validation_update()
        name_box.textEdited.connect(handle_name)

        layout.addWidget(name_label, row, 0)
        layout.addWidget(name_box, row, 1)
        row += 1

        # address

        address_label = QLabel(self)
        address_label.setText("Address")

        address_box = QLineEdit(self)
        address_box.setText(hex(self.instance.project.entry) if self._addr is None else hex(self._addr))

        def handle_address(_):
            nonlocal validation_failures
            key = {'addr'}
            if parse_address() is not None:
                validation_failures -= key
            else:
                validation_failures |= key
            validation_update()

        def parse_address():
            txt = address_box.text()
            try:
                return self.instance.project.kb.labels.lookup(txt)
            except KeyError:
                pass

            try:
                return int(txt, 16)
            except ValueError:
                return None

        address_box.textEdited.connect(handle_address)
        layout.addWidget(address_label, row, 0)
        layout.addWidget(address_box, row, 1)
        row += 1

        # template

        template_label = QLabel(self)
        template_label.setText("Template")

        template_combo = QComboBox()
        template_combo.addItem("Blank State", 'blank')
        template_combo.addItem("Call state", 'call')
        template_combo.addItem("Entry state", 'entry')
        template_combo.addItem("Full-init state", 'full')

        def handle_template(_):
            base_allowed = template_combo.currentData() in ('blank', 'call')
            base_state_combo.setHidden(not base_allowed)
            base_state_label.setHidden(not base_allowed)

        template_combo.currentIndexChanged.connect(handle_template)

        layout.addWidget(template_label, row, 0)
        layout.addWidget(template_combo, row, 1)
        row += 1

        # base state

        base_state_label = QLabel(self)
        base_state_label.setText('Base state')

        base_state_combo = QStateComboBox(self.instance, self)
        self._base_state_combo = base_state_combo

        layout.addWidget(base_state_label, row, 0)
        layout.addWidget(base_state_combo, row, 1)
        row += 1

        # mode

        mode_label = QLabel(self)
        mode_label.setText("Mode")

        mode_combo = QComboBox(self)
        mode_combo.addItem("Symbolic", "symbolic")
        mode_combo.addItem("Static", "static")
        mode_combo.addItem("Fast-path", "fastpath")
        mode_combo.addItem("Tracing", "tracing")
        self._mode_combo = mode_combo

        def mode_changed():
            self._options.clear()
            self._options.update(angr.sim_options.modes[mode_combo.currentData()])
            for child in children_items:
                child.setCheckState(0, Qt.Checked if child.text(0) in self._options else Qt.Unchecked)
        mode_combo.currentIndexChanged.connect(mode_changed)
        self._options.clear()
        self._options.update(angr.sim_options.modes[mode_combo.currentData()])

        layout.addWidget(mode_label, row, 0)
        layout.addWidget(mode_combo, row, 1)
        row += 1

        # options tree

        options_label = QLabel(self)
        options_label.setText("Options")

        options_tree = QTreeWidget(self)
        options_tree.setHeaderHidden(True)
        children_items = []
        for name, members in angr.sim_options.__dict__.items():
            if type(members) is not set:
                continue
            if name == 'resilience_options':
                continue
            parent = QTreeWidgetItem(options_tree)
            parent.setText(0, name)
            parent.setFlags(parent.flags() | Qt.ItemIsTristate | Qt.ItemIsUserCheckable)
            for option in members:
                child = QTreeWidgetItem(parent)
                child.setText(0, option)
                child.setFlags(child.flags() | Qt.ItemIsUserCheckable)
                child.setCheckState(0, Qt.Checked if option in self._options else Qt.Unchecked)
                children_items.append(child)
        parent = QTreeWidgetItem(options_tree)
        parent.setText(0, "All options")
        parent.setFlags(parent.flags() | Qt.ItemIsTristate | Qt.ItemIsUserCheckable)
        for option in {x for x in angr.sim_options.__dict__.values() if type(x) is str and is_option(x)}:
            child = QTreeWidgetItem(parent)
            child.setText(0, option)
            child.setFlags(child.flags() | Qt.ItemIsUserCheckable)
            child.setCheckState(0, Qt.Checked if option in self._options else Qt.Unchecked)
            children_items.append(child)

        def maintain_model(item: QTreeWidgetItem, _):
            option = item.text(0)
            if not is_option(option):
                return

            checked = item.checkState(0)
            if (option in self._options) == checked:
                return

            if checked:
                self._options.add(option)
            else:
                self._options.remove(option)

            for child in children_items:
                if child is not item and child.text(0) == option:
                    child.setCheckState(0, checked)

        options_tree.itemChanged.connect(maintain_model)

        layout.addWidget(options_label, row, 0)
        layout.addWidget(options_tree, row, 1)
        row += 1

        # options filter

        options_filter_label = QLabel(self)
        options_filter_label.setText("")

        options_filter_box = QLineEdit(self)
        options_filter_box.setPlaceholderText("Filter")

        def do_filter(text):
            for child in children_items:
                child.setHidden(text.upper() not in child.text(0))
        options_filter_box.textEdited.connect(do_filter)

        layout.addWidget(options_filter_label, row, 0)
        layout.addWidget(options_filter_box, row, 1)
        row += 1

        # buttons

        ok_button = QPushButton(self)
        ok_button.setText('OK')
        def do_ok():
            name = name_box.text()
            template = template_combo.currentData()
            addr = parse_address()
            base_state = base_state_combo.state
            mode = mode_combo.currentData()
            if template in ('blank', 'call') and base_state is not None:
                if template == 'blank':
                    self.state = self.instance.project.factory.blank_state(addr=addr, base_state=base_state, options=self._options)
                else:
                    self.state = self.instance.project.factory.call_state(addr, base_state=base_state, options=self._options)
                self.state.gui_data.base_name = base_state.gui_data.name
            else:
                if template == 'blank':
                    self.state = self.instance.project.factory.blank_state(addr=addr, mode=mode, options=self._options)
                elif template == 'call':
                    self.state = self.instance.project.factory.call_state(addr, mode=mode, options=self._options)
                elif template == 'entry':
                    self.state = self.instance.project.factory.entry_state(mode=mode, options=self._options)
                else:
                    self.state = self.instance.project.factory.full_init_state(mode=mode, options=self._options)
                self.state.gui_data.base_name = name
                self.state.gui_data.is_base = True

            self.state.gui_data.name = name
            self.state.gui_data.is_original = True

            if self._create_simgr:
                self.instance.workspace.create_simulation_manager(self.state, name)

            self.close()

        ok_button.clicked.connect(do_ok)
        def validation_update():
            ok_button.setDisabled(bool(validation_failures))

        cancel_button = QPushButton(self)
        cancel_button.setText('Cancel')
        def do_cancel():
            self.close()
        cancel_button.clicked.connect(do_cancel)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)

        self.main_layout.addLayout(layout)
        self.main_layout.addLayout(buttons_layout)
