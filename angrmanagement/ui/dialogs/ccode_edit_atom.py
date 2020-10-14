from typing import Optional, Tuple, List

import pyvex

from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QGridLayout

from angr.analyses.decompiler.structured_codegen.c import CExpression, CBinaryOp, CConstant
from angr.analyses.viscosity.viscosity import Viscosity

# AIL binary operations
AIL_BINOP_NAME2REPR = {
    "CmpLE": "<=",
    "CmpLT": "<",
    "CmpGE": ">=",
    "CmpGT": ">",
    "CmpEQ": "==",
    "CmpNE": "!=",
}

AIL_BINOP_REPR2NAME = dict((v, k) for k, v in AIL_BINOP_NAME2REPR.items())

# VEX binary operations
AIL_BINOP_TO_VEX_BINOP = {
    'CmpLE': 'Iop_CmpLE{b}U',
    'CmpLT': 'Iop_CmpLT{b}U',
    'CmpEQ': 'Iop_CmpEQ{b}',
    'CmpNE': 'Iop_CmpNE{b}',
}


def ailop2vexop(ail_op: str, bits: int):
    if ail_op in AIL_BINOP_TO_VEX_BINOP:
        return AIL_BINOP_TO_VEX_BINOP[ail_op].format(b=bits)
    return None


class CCodeEditAtom(QDialog):
    def __init__(self, instance, node: CExpression, parent=None):
        super().__init__(parent)

        self.instance = instance
        self.node = node
        self._block = None
        self._vex_stmt_idx: Optional[int] = None
        self._vex_stmt = None

        self._new_atom_edit: QLineEdit = None

        self._extract_vex_statement()

        self.setWindowTitle('Code atom editor')

        self.main_layout = QVBoxLayout()
        self._init_widgets()
        self.setLayout(self.main_layout)

        self.show()

    #
    # Private methods
    #

    def _extract_vex_statement(self):
        if isinstance(self.node, (CBinaryOp, CConstant)):
            vex_block_addr = self.node.tags.get('vex_block_addr', None)
            self._vex_stmt_idx = self.node.tags.get('vex_stmt_idx', None)

            if vex_block_addr is not None and self._vex_stmt_idx is not None and self._vex_stmt_idx >= 0:
                # note that we do not support modifying offsets for DEFAULT_EXIT
                self._block = self.instance.project.factory.block(vex_block_addr, cross_insn_opt=False)
                self._vex_stmt = self._block.vex.statements[self._vex_stmt_idx]

    def _init_widgets(self):

        upper_layout = QGridLayout()

        # atom type
        atom_type_label = QLabel("Atom type")
        atom_type = QLabel(self)
        if isinstance(self.node, CBinaryOp):
            atom_type.setText("Binary operator")
        elif isinstance(self.node, CConstant):
            atom_type.setText("Constant")
        else:
            atom_type.setText("Unsupported")
        upper_layout.addWidget(atom_type_label, 0, 0)
        upper_layout.addWidget(atom_type, 0, 1)

        # atom
        atom_label = QLabel("Atom")
        atom = QLabel(self)
        if isinstance(self.node, CBinaryOp):
            atom.setText(AIL_BINOP_NAME2REPR.get(self.node.op, self.node.op))
        elif isinstance(self.node, CConstant):
            atom.setText(str(self.node.value))
        else:
            atom.setText("Unsupported")
        upper_layout.addWidget(atom_label, 1, 0)
        upper_layout.addWidget(atom, 1, 1)

        # VEX statement
        vex_stmt_label = QLabel("VEX statement")
        vex_stmt = QLabel(self)
        if self._vex_stmt is not None:
            vex_stmt.setText("%#x:%d   %s" % (self._block.addr, self._vex_stmt_idx, str(self._vex_stmt)))
        else:
            vex_stmt.setText("Unsupported")
        upper_layout.addWidget(vex_stmt_label, 2, 0)
        upper_layout.addWidget(vex_stmt, 2, 1)

        # new atom
        new_atom_label = QLabel("New")
        new_atom_edit = QLineEdit(self)
        self._new_atom_edit = new_atom_edit
        self._new_atom_edit.textChanged.connect(self._on_new_atom_changed)
        upper_layout.addWidget(new_atom_label, 3, 0)
        upper_layout.addWidget(self._new_atom_edit, 3, 1)

        self.main_layout.addLayout(upper_layout)

        # buttons
        ok_button = QPushButton(self)
        ok_button.setText('OK')
        ok_button.setEnabled(False)
        ok_button.clicked.connect(self._on_ok_clicked)
        self._ok_button = ok_button

        cancel_button = QPushButton(self)
        cancel_button.setText('Cancel')
        cancel_button.clicked.connect(self._on_cancel_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)

        self.main_layout.addLayout(buttons_layout)

    def _attempt_patching(self) -> Tuple[bool,List]:
        if self._block is None or self._vex_stmt_idx is None or self._vex_stmt is None:
            return False, [ ]

        # build the new VEX block
        if isinstance(self.node, CBinaryOp):
            # binary operator
            text = self._new_atom_edit.text().strip()

            binop_name = AIL_BINOP_REPR2NAME.get(text, None)
            if binop_name is None:
                return False, [ ]
            vex_binop_name = ailop2vexop(binop_name, self.instance.project.arch.bits)
            if vex_binop_name is None:
                return False, [ ]

            vex_op_int = pyvex.enums_to_ints[vex_binop_name]  # shall not fail unless vex_binop_name is incorrect

            changed_vex_block = self._block.vex.copy()
            the_stmt = changed_vex_block.statements[self._vex_stmt_idx]
            if not isinstance(the_stmt, pyvex.stmt.WrTmp) or not isinstance(the_stmt.data, pyvex.expr.Binop):
                return False, [ ]

            the_stmt.data._op = None
            the_stmt.data.op_int = vex_op_int

        elif isinstance(self.node, CConstant):
            # constant
            text = self._new_atom_edit.text().strip()
            try:
                new_value = int(text)
            except (ValueError, TypeError):
                # Cannot convert the string to an integer
                return False, [ ]

            changed_vex_block = self._block.vex.copy()
            the_stmt = changed_vex_block.statements[self._vex_stmt_idx]

            if isinstance(the_stmt, pyvex.stmt.WrTmp):
                if isinstance(the_stmt.data, pyvex.expr.Const):
                    const = the_stmt.data.con.__class__(new_value)
                    the_stmt.data = pyvex.expr.Const(const)
                elif isinstance(the_stmt.data, pyvex.expr.Binop):
                    args = the_stmt.data.args
                    if isinstance(the_stmt.data.args[1], pyvex.expr.Const):
                        const = args[1].con.__class__(new_value)
                        the_stmt.data.args = (args[0], pyvex.expr.Const(const))
                    elif isinstance(the_stmt.data.args[0], pyvex.expr.Const):
                        const = args[0].con.__class__(new_value)
                        the_stmt.data.args = (pyvex.expr.Const(const), args[1])
            elif isinstance(the_stmt, pyvex.stmt.Put) and isinstance(the_stmt.data, pyvex.expr.Const):
                const = the_stmt.data.con.__class__(new_value)
                the_stmt.data = pyvex.expr.Const(const)

        else:
            return False, [ ]

        v = self.instance.project.analyses.Viscosity(self._block, changed_vex_block)

        if v.result:
            return True, v.result

        return False, [ ]

    #
    # Event handlers
    #

    def _on_new_atom_changed(self, new_text):
        if not new_text:
            return

        can_patch, patches = self._attempt_patching()
        self._ok_button.setEnabled(can_patch)

    def _on_ok_clicked(self):
        can_patch, edits = self._attempt_patching()
        if can_patch:
            for edit in edits:
                patch = Viscosity.edit_to_patch(edit, self.instance.project)
                self.instance.kb.patches.add_patch_obj(patch)
            self.instance.patches.am_event()
        self.close()

    def _on_cancel_clicked(self):
        self.close()
