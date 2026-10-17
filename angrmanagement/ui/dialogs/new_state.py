from __future__ import annotations

from typing import TYPE_CHECKING

import angr
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from angrmanagement.present.symexec import (
    StateMetadata,
    StateSpec,
    add_state,
    build_state,
    is_option,
    parse_state_address,
)
from angrmanagement.ui.dialogs.env_config import EnvConfig
from angrmanagement.ui.dialogs.fs_mount import FilesystemMount
from angrmanagement.ui.widgets import QStateComboBox
from angrmanagement.utils.namegen import NameGenerator

from .socket_config import SocketConfig

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class NewState(QDialog):
    """
    Dialog to create a new simulation state.
    """

    def __init__(
        self,
        workspace: Workspace,
        instance: Instance,
        addr: int | None = None,
        create_simgr: bool = False,
        parent=None,
        push_to_instance: bool = True,
    ) -> None:
        super().__init__(parent)

        # initialization

        self.workspace = workspace
        self.instance = instance
        self.state = None  # output

        self._options = set()
        self._addr = addr
        self._create_simgr = create_simgr  # Shall we create a new simgr after clicking OK?

        # Shall we push the new state to instance.stats and call states.am_event(src="new", state=self.state)
        self._push_to_instance = push_to_instance

        self._editor: QTextEdit | None = None
        self._ok_button = None

        self._args: list[str] | None = None
        self._env_config: list[tuple[str, str]] = []
        self._fs_config: list[tuple[str, str]] | None = None
        self._sockets_config = None

        self.setWindowTitle("New State")

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        layout = QGridLayout()
        row = 0

        validation_failures = set()

        # name

        name_label = QLabel(self)
        name_label.setText("Name")

        name_box = QLineEdit(self)
        name_box.setText(NameGenerator.random_name())

        def handle_name(txt: str) -> None:
            nonlocal validation_failures
            key = {"name"}
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

        def handle_address(_) -> None:
            nonlocal validation_failures
            key = {"addr"}
            if parse_address() is not None:
                validation_failures -= key
            else:
                validation_failures |= key
            validation_update()

        def parse_address():
            return parse_state_address(self.instance, address_box.text())

        address_box.textEdited.connect(handle_address)
        layout.addWidget(address_label, row, 0)
        layout.addWidget(address_box, row, 1)
        row += 1

        # template

        template_label = QLabel(self)
        template_label.setText("Template")

        template_combo = QComboBox()
        template_combo.addItem("Blank State", "blank")
        template_combo.addItem("Call state", "call")
        template_combo.addItem("Entry state", "entry")
        template_combo.addItem("Full-init state", "full")

        def handle_template(_) -> None:
            base_allowed = template_combo.currentData() in ("blank", "call")
            base_state_combo.setHidden(not base_allowed)
            base_state_label.setHidden(not base_allowed)
            args_allowed = template_combo.currentData() in ("entry",)
            args_label.setHidden(not args_allowed)
            args_edit.setHidden(not args_allowed)
            env_label.setHidden(not args_allowed)
            env_button.setHidden(not args_allowed)

        template_combo.currentIndexChanged.connect(handle_template)

        layout.addWidget(template_label, row, 0)
        layout.addWidget(template_combo, row, 1)
        row += 1

        # base state

        base_state_label = QLabel(self)
        base_state_label.setText("Base state")

        base_state_combo = QStateComboBox(self.instance, self)

        layout.addWidget(base_state_label, row, 0)
        layout.addWidget(base_state_combo, row, 1)
        row += 1

        # args
        args_label = QLabel(self)
        args_label.setText("Args")

        args_edit = QTextEdit(self)
        args_edit.setAcceptRichText(False)
        args_edit.setFixedHeight(60)

        def handle_args() -> None:
            self._args = [self.instance.project.filename.encode() or b"dummy_filename"] + [
                x.encode() for x in args_edit.toPlainText().split()
            ]

        args_edit.textChanged.connect(handle_args)

        layout.addWidget(args_label, row, 0)
        layout.addWidget(args_edit, row, 1)
        row += 1

        # env_config
        env_label = QLabel(self)
        env_label.setText("Environment")
        env_button = QPushButton(self)
        env_button.setText("Change")

        layout.addWidget(env_label, row, 0)
        layout.addWidget(env_button, row, 1)

        def env_edit_button() -> None:
            env_dialog = EnvConfig(env_config=self._env_config, instance=self.instance, parent=self)
            env_dialog.exec_()
            self._env_config = env_dialog.env_config
            env_button.setText(f"{len(self._env_config)} Items")

        env_button.clicked.connect(env_edit_button)

        row += 1

        # fs_mount
        fs_label = QLabel(self)
        fs_label.setText("Filesystem")
        fs_button = QPushButton(self)
        fs_button.setText("Change")

        layout.addWidget(fs_label, row, 0)
        layout.addWidget(fs_button, row, 1)

        def fs_edit_button() -> None:
            fs_dialog = FilesystemMount(fs_config=self._fs_config, instance=self.instance, parent=self)
            fs_dialog.exec_()
            self._fs_config = fs_dialog.fs_config
            fs_button.setText(f"{len(self._fs_config)} Items")

        fs_button.clicked.connect(fs_edit_button)

        row += 1

        # socket support
        socket_label = QLabel(self)
        socket_label.setText("Sockets")
        socket_button = QPushButton(self)
        socket_button.setText("Change")

        layout.addWidget(socket_label, row, 0)
        layout.addWidget(socket_button, row, 1)

        def socket_edit_button() -> None:
            socket_dialog = SocketConfig(socket_config=self._sockets_config, instance=self.instance)
            socket_dialog.exec_()
            self._sockets_config = socket_dialog.socket_config
            # socket_button.setText("{} Items".format(len(self._sockets_config)))

        socket_button.clicked.connect(socket_edit_button)

        row += 1

        # mode

        mode_label = QLabel(self)
        mode_label.setText("Mode")

        mode_combo = QComboBox(self)
        mode_combo.addItem("Symbolic", "symbolic")
        mode_combo.addItem("Static", "static")
        mode_combo.addItem("Fast-path", "fastpath")
        mode_combo.addItem("Tracing", "tracing")

        def mode_changed() -> None:
            self._options.clear()
            self._options.update(angr.sim_options.modes[mode_combo.currentData()])
            for child in children_items:
                child.setCheckState(
                    0, Qt.CheckState.Checked if child.text(0) in self._options else Qt.CheckState.Unchecked
                )

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
            if not isinstance(members, set):
                continue
            if name == "resilience_options":
                continue
            parent = QTreeWidgetItem(options_tree)
            parent.setText(0, name)
            parent.setFlags(parent.flags() | Qt.ItemFlag.ItemIsAutoTristate | Qt.ItemFlag.ItemIsUserCheckable)
            for option in members:
                child = QTreeWidgetItem(parent)
                child.setText(0, option)
                child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                child.setCheckState(0, Qt.CheckState.Checked if option in self._options else Qt.CheckState.Unchecked)
                children_items.append(child)
        parent = QTreeWidgetItem(options_tree)
        parent.setText(0, "All options")
        parent.setFlags(parent.flags() | Qt.ItemFlag.ItemIsAutoTristate | Qt.ItemFlag.ItemIsUserCheckable)
        for option in {x for x in angr.sim_options.__dict__.values() if isinstance(x, str) and is_option(x)}:
            child = QTreeWidgetItem(parent)
            child.setText(0, option)
            child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            child.setCheckState(0, Qt.CheckState.Checked if option in self._options else Qt.CheckState.Unchecked)
            children_items.append(child)

        def maintain_model(item: QTreeWidgetItem, _) -> None:
            option = item.text(0)
            if not is_option(option):
                return

            checked = item.checkState(0) == Qt.CheckState.Checked
            if (option in self._options) == checked:
                return

            if checked:
                self._options.add(option)
            else:
                self._options.remove(option)

            for child in children_items:
                if child is not item and child.text(0) == option:
                    child.setCheckState(0, Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)

        options_tree.itemChanged.connect(maintain_model)

        layout.addWidget(options_label, row, 0)
        layout.addWidget(options_tree, row, 1)
        row += 1

        # options filter

        options_filter_label = QLabel(self)
        options_filter_label.setText("")

        options_filter_box = QLineEdit(self)
        options_filter_box.setPlaceholderText("Filter")

        def do_filter(text: str) -> None:
            for child in children_items:
                child.setHidden(text.upper() not in child.text(0))

        options_filter_box.textEdited.connect(do_filter)

        layout.addWidget(options_filter_label, row, 0)
        layout.addWidget(options_filter_box, row, 1)
        row += 1

        # buttons

        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)

        def do_ok() -> None:
            name = name_box.text()
            spec = StateSpec(
                name,
                address_box.text(),
                template=template_combo.currentData(),
                base_state=base_state_combo.state,
                args=None if self._args is None else args_edit.toPlainText(),
                mode=mode_combo.currentData(),
                env=[(pair[0], pair[1]) for pair in self._env_config],
                fs_mounts=list(self._fs_config or []),
                sockets=self._sockets_config,
                options=self._options,
            )
            self.state = build_state(self.instance, spec)
            add_state(self.workspace, self.instance, self.state, self._push_to_instance, self._create_simgr)
            self.close()

        ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(do_ok)

        def validation_update() -> None:
            ok_button.setDisabled(bool(validation_failures))

        buttons.rejected.connect(self.close)

        self.main_layout.addLayout(layout)
        self.main_layout.addWidget(buttons)

        handle_template(None)


__all__ = ["NewState", "StateMetadata", "is_option"]
