"""
The Qt side of the shared dialog rules: the generic form dialog the Qt UI services show a form in, and the dialogs
that now check with the shared rules (the breakpoint dialog's address box takes a function name).
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use,unused-argument

from __future__ import annotations

import os
import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import angr
from common import create_qapp, test_location  # pylint: disable=import-error
from PySide6.QtWidgets import QCheckBox, QLabel, QLineEdit, QPlainTextEdit

from angrmanagement.data.breakpoint import Breakpoint, BreakpointType
from angrmanagement.data.instance import Instance
from angrmanagement.present.dialogs import hook_form, jump_to_form
from angrmanagement.present.forms import Form, FormField
from angrmanagement.ui.dialogs.breakpoint import BreakpointDialog
from angrmanagement.ui.dialogs.form import FormDialog
from angrmanagement.ui.qt_services import QtServices


def fauxware_instance() -> Instance:
    instance = Instance()
    project = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
    project.analyses.CFGFast(normalize=True)
    instance.project.am_obj = project
    return instance


class TestFormDialog(unittest.TestCase):
    def setUp(self) -> None:
        create_qapp()

    def test_the_check_the_status_line_and_the_values(self) -> None:
        dialog = FormDialog(jump_to_form(fauxware_instance()))
        box = dialog._editors["address"]
        assert isinstance(box, QLineEdit)
        box.setText("no such function")
        assert dialog._status.text() == "Invalid" and not dialog._ok.isEnabled()
        box.setText("main")
        assert dialog._status.text() == "Valid" and dialog._ok.isEnabled()
        dialog._accept()
        assert dialog.values == {"address": "main"}

    def test_a_field_that_follows_another(self) -> None:
        dialog = FormDialog(hook_form(0x400100))
        group = dialog._editors["preset"][1]
        group.button(0).setChecked(True)  # "assertion", the first preset by name
        code = dialog._editors["code"]
        assert isinstance(code, QPlainTextEdit) and code.toPlainText().startswith("@project.hook(addr=0x400100")

    def test_the_services_show_a_form_and_answer_its_values(self) -> None:
        form = Form("A form", [FormField("on", "On", "bool", False), FormField("note", "Note", "label", "read me")])
        answers: list[Any] = []

        def accept(dialog: FormDialog) -> int:
            box = dialog._editors["on"]
            assert isinstance(box, QCheckBox) and isinstance(dialog._editors["note"], QLabel)
            box.setChecked(True)
            dialog._accept()
            return 1

        with patch.object(FormDialog, "exec_", accept):
            QtServices().ask_form_async(form, answers.append)
        assert answers == [{"on": True, "note": "read me"}]


class TestBreakpointDialog(unittest.TestCase):
    def setUp(self) -> None:
        create_qapp()

    def test_the_address_box_takes_a_function_name(self) -> None:
        instance = fauxware_instance()
        workspace: Any = SimpleNamespace(main_instance=instance)
        bp = Breakpoint(BreakpointType.Execute, 0x400100)
        dialog = BreakpointDialog(bp, workspace)
        # the box looked the name up on the workspace it was given, which has no project: AttributeError
        box: Any = dialog._address_box
        ok_button: Any = dialog._ok_button
        kb: Any = instance.kb
        box.setText("main")
        assert box.target == kb.functions["main"].addr
        assert ok_button.isEnabled()
        dialog._on_ok_clicked()
        assert bp.addr == kb.functions["main"].addr


if __name__ == "__main__":
    unittest.main()
