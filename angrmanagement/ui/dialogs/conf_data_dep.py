from typing import Optional, TYPE_CHECKING, Dict, Any
import logging

from PySide2 import QtWidgets, QtCore
from PySide2.QtCore import Slot

import angr

if TYPE_CHECKING:
    from ...data.instance import Instance
    from angr import Project, SimState

_l = logging.getLogger(__name__)


def unwrap_line_edit_text(widg: QtWidgets.QLineEdit) -> Optional[str]:
    """
    Returns the text in a QLineEdit, if it isn't empty. Otherwise, returns None
    :param widg: QlineEdit whose text must be unwrapped
    """
    return widg.text() if widg.text() else None


def prepare_state(proj: 'Project', start_addr: int) -> 'SimState':
    """Prepares a state at the given starting address with the required options for tracking SimActions"""
    init_state = proj.factory.blank_state(addr=start_addr, mode='symbolic')

    # Ensure SimActions are captured during symbolic execution
    for opt in angr.options.refs:
        init_state.options.add(opt)

    return init_state


class ConfigureDataDep(QtWidgets.QDialog):
    """
    QDialog to be used to ascertain the parameters for a DataDependencyGraphAnalysis
    Depending on context, different parameters will be asked for.
    """

    def __init__(self, parent: QtWidgets.QWidget, instance: 'Instance', addr: int, ):
        super().__init__(parent)

        # Initialization
        self._instance = instance
        self._analysis_params = {  # Output
            'end_state': None,
            'start_addr': 0,
            'end_addr': addr,
            'block_addrs': [],
        }

        self._go_btn: Optional[QtWidgets.QPushButton] = None
        self._cancel_btn: Optional[QtWidgets.QPushButton] = None
        self._start_addr_line_edit: Optional[QtWidgets.QLineEdit] = None
        self._end_addr_line_edit: Optional[QtWidgets.QLineEdit] = None

        self.setWindowTitle("Configure Data Dependency Graph")

        self._lm = QtWidgets.QVBoxLayout()
        self._init_widgets()
        self.setLayout(self._lm)

    @property
    def analysis_params(self) -> Dict[str, Any]:
        return self._analysis_params

    @property
    def start_addr(self) -> int:
        return self._analysis_params.setdefault('start_addr', self._instance.project.entry)

    @property
    def end_addr(self) -> int:
        return self._analysis_params.get('end_addr', 0)

    @Slot()
    def _prepare_for_accept(self):
        """
        Slot to handle a user clicking on the 'Go' button, to close the dialog
        Prepares the return dictionary with all parameters as they currently stand
        """
        try:
            self._analysis_params['start_addr'] = int(unwrap_line_edit_text(self._start_addr_line_edit), 16)

            # TODO: Create a simulation manager and use find=end_addr?
            start_state = prepare_state(self._instance.project, self.start_addr)
            simgr = self._instance.project.factory.simgr(start_state)
            simgr.explore(find=self.end_addr)

            if not simgr.found:
                # This isn't a reachable state, no point in proceeding
                _l.error("Unable to reach %s from %s in symbolic exec!", hex(self.end_addr), hex(self.start_addr))
                self.reject()

            self._analysis_params['end_state'] = simgr.found[0]

            self.accept()
        except KeyError:
            _l.error("Unexpected key set in prepare_for_accept")
            self.reject()

    @Slot()
    def _handle_address_change(self):
        """
        Slot to handle a text change in any QLineEdit that takes in program addresses
        Ensures the address is appropriate, otherwise prevents dialog acceptance
        """

        sender = QtCore.QObject.sender(self)
        if not sender or not isinstance(sender, QtWidgets.QLineEdit):
            return

        is_valid = True
        sender_text = sender.text()

        try:
            # Ensure input is numeric
            value = int(sender_text, 16)

            # Ensure end_addr >= start_addr if applicable
            if sender is self._start_addr_line_edit and value > self.end_addr:
                raise ValueError()

        except ValueError:
            is_valid = False
        finally:
            self._go_btn.setEnabled(is_valid)

    def _init_widgets(self):
        form_layout = QtWidgets.QFormLayout()

        # Create go button, which will accept the dialog
        self._go_btn = QtWidgets.QPushButton("Go")
        self._go_btn.setDefault(True)
        self._go_btn.setDisabled(True)
        self._go_btn.clicked.connect(self._prepare_for_accept)

        # Create cancel button, which will reject the dialog
        self._cancel_btn = QtWidgets.QPushButton("Cancel")
        self._cancel_btn.clicked.connect(self.reject)

        # Create line edit for input of starting address
        self._start_addr_line_edit = QtWidgets.QLineEdit(self)
        self._start_addr_line_edit.textEdited.connect(self._handle_address_change)
        form_layout.addRow('Starting Address', self._start_addr_line_edit)

        # Create read-only line edit containing hex string of ending address
        self._end_addr_line_edit = QtWidgets.QLineEdit(self)
        self._end_addr_line_edit.setText(hex(self.end_addr))
        self._end_addr_line_edit.setEnabled(False)
        form_layout.addRow('Ending Address', self._end_addr_line_edit)

        self._lm.addLayout(form_layout)

        # Layout buttons horizontally
        buttons_layout = QtWidgets.QHBoxLayout()
        buttons_layout.addWidget(self._go_btn)
        buttons_layout.addWidget(self._cancel_btn)

        self._lm.addLayout(buttons_layout)
