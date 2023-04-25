from typing import TYPE_CHECKING, Any, Optional

from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from PySide6.QtWidgets import (
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.utils.func import function_prototype_str

if TYPE_CHECKING:
    from angr.knowledge_plugins import Function


class DependsOn(QDialog):
    def __init__(self, addr: int, operand, instr=None, func: Optional["Function"] = None, parent=None):
        super().__init__(parent)

        self._addr = addr
        self._operand = operand
        self._instruction = instr
        self._function = func

        # output
        self.location: Optional[int] = None
        self.arg: Optional[Any] = None
        self.reg: Optional[Any] = None

        # UI widgets
        self._instr_layout: QHBoxLayout = None
        self._func_layout: QHBoxLayout = None
        self._arg_widget: QWidget = None
        self._reg_widget: QWidget = None

        self._before_radio: QRadioButton = None
        self._after_radio: QRadioButton = None
        self._arg_layout: QVBoxLayout = None
        self._arg_radiobox: QRadioButton = None
        self._arg_box: QLineEdit = None
        self._reg_layout: QVBoxLayout = None
        self._reg_radiobox: QRadioButton = None
        self._reg_box: QLineEdit = None

        self._init_widgets()

    def _init_widgets(self):
        # the instruction
        instr_lbl = QLabel("Instruction")
        instr_box = QLineEdit("TODO")
        instr_box.setReadOnly(True)

        self._instr_layout = QHBoxLayout()
        self._instr_layout.addWidget(instr_lbl)
        self._instr_layout.addWidget(instr_box)

        # the function
        func_lbl = QLabel("Function")
        func_box = QLineEdit("TODO")
        func_box.setReadOnly(True)

        self._func_layout = QHBoxLayout()
        self._func_layout.addWidget(func_lbl)
        self._func_layout.addWidget(func_box)

        #
        # location
        #
        location_group = QGroupBox("Location")

        self._before_radio = QRadioButton("Before the instruction")
        self._after_radio = QRadioButton("After the instruction")
        location_layout = QVBoxLayout()
        location_layout.addWidget(self._before_radio)
        location_layout.addWidget(self._after_radio)
        location_layout.addStretch(1)

        self._before_radio.setChecked(True)

        location_group.setLayout(location_layout)

        #
        # target atoms
        #

        # function argument
        self._arg_radiobox = QRadioButton("Function argument")
        self._arg_radiobox.clicked.connect(self._on_targetatoms_radiobutton_clicked)
        self._arg_box = QLineEdit("0")

        # register
        self._reg_radiobox = QRadioButton("Register")
        self._reg_radiobox.clicked.connect(self._on_targetatoms_radiobutton_clicked)
        self._reg_box = QLineEdit("")

        atom_type_group = QGroupBox("Atom type")
        atom_type_layout = QVBoxLayout()
        atom_type_layout.addWidget(self._arg_radiobox)
        # atom_type_layout.addWidget(self._reg_radiobox)
        atom_type_layout.addStretch(1)
        atom_type_group.setLayout(atom_type_layout)

        atom_layout = QVBoxLayout()
        arg_layout = QHBoxLayout()
        arg_lbl = QLabel("Argument index")
        self._arg_widget = QWidget()
        self._arg_widget.setLayout(arg_layout)
        arg_layout.addWidget(arg_lbl)
        arg_layout.addWidget(self._arg_box)

        reg_layout = QHBoxLayout()
        reg_lbl = QLabel("Register name")
        self._reg_widget = QWidget()
        self._reg_widget.setLayout(reg_layout)
        reg_layout.addWidget(reg_lbl)
        reg_layout.addWidget(self._reg_box)

        atom_layout.addWidget(self._arg_widget)
        atom_layout.addWidget(self._reg_widget)

        self._arg_radiobox.setChecked(True)
        self._reg_widget.setHidden(True)

        #
        # buttons
        #
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self._on_ok_clicked)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self._on_cancel_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(ok_btn)
        buttons_layout.addWidget(cancel_btn)

        layout = QVBoxLayout()
        if self._function is not None:
            func_box.setText(function_prototype_str(self._function))
            layout.addLayout(self._func_layout)
        else:
            layout.addLayout(self._instr_layout)
        layout.addWidget(location_group)
        layout.addWidget(atom_type_group)
        layout.addLayout(atom_layout)
        layout.addLayout(buttons_layout)

        self.setLayout(layout)

    #
    # Events
    #

    def _targetatoms_hide_all(self):
        self._arg_widget.setHidden(True)
        self._reg_widget.setHidden(True)

    def _on_targetatoms_radiobutton_clicked(self):
        self._targetatoms_hide_all()
        if self._arg_radiobox.isChecked():
            self._arg_widget.setHidden(False)
        elif self._reg_radiobox.isChecked():
            self._reg_widget.setHidden(False)

    def _on_ok_clicked(self):
        if self._before_radio.isChecked():
            self.location = OP_BEFORE
        else:
            self.location = OP_AFTER

        if self._arg_radiobox.isChecked():
            try:
                self.arg = int(self._arg_box.text())
            except ValueError:
                # invalid argument index
                QMessageBox(self).critical(
                    self,
                    "Invalid argument index",
                    'The given function argument index "%s" is unsupported. Only integers are allowed.'
                    % self._arg_box.text(),
                    buttons=QMessageBox.Ok,
                )
                return
        else:
            raise NotImplementedError

        self.close()

    def _on_cancel_clicked(self):
        self.location = None
        self.arg = None
        self.reg = None
        self.close()
