from __future__ import annotations

import copy
import threading
import time
import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from common import create_qapp
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QDialog, QDialogButtonBox

from angrmanagement.logic.debugger.gdb import GDBRuntime, RuntimeErrorBase
from angrmanagement.ui.dialogs.runtime_breakpoint import RuntimeBreakpointDialog
from angrmanagement.ui.dialogs.runtime_connection import RuntimeConnectionDialog
from angrmanagement.ui.dialogs.runtime_rule import RuntimeRuleDialog
from angrmanagement.ui.views.runtime_view import RuntimeHistoryChart, RuntimeView


class _RuntimeDouble:
    """A target boundary used to test GUI threading and user interactions without GDB."""

    preview_rule = staticmethod(GDBRuntime.preview_rule)

    def __init__(self):
        self.data = {"state": "disconnected", "rules": [], "events": [], "output": []}
        self.callbacks = []
        self.calls = []
        self.select_thread = MagicMock()
        self.select_frame = MagicMock()
        self.write_register = MagicMock()
        self.enable_breakpoint = MagicMock()
        self.remove_breakpoint = MagicMock()
        self.static_to_runtime = MagicMock()

    def subscribe(self, callback):
        self.callbacks.append(callback)
        return lambda: self.callbacks.remove(callback)

    def snapshot(self):
        return copy.deepcopy(self.data)

    def checked(self, operation, generation, pc=None, *, states=None, thread_id=None, frame_level=None):
        if generation != self.data.get("generation", 0):
            raise RuntimeError("The runtime session changed")
        if states is not None and self.data.get("state") not in states:
            raise RuntimeError("The runtime state changed")
        if pc is not None and self.data.get("frame", {}).get("addr") != pc:
            raise RuntimeError("The stopped PC changed")
        if thread_id is not None and self.data.get("selected_thread") != thread_id:
            raise RuntimeError("The selected thread changed")
        if frame_level is not None and self.data.get("frame", {}).get("level") != frame_level:
            raise RuntimeError("The selected frame changed")
        return operation()

    def send_input(self, text):
        self.calls.append(("input", text))

    def refresh(self):
        self.calls.append(("refresh", threading.get_ident()))
        return self.snapshot()

    def continue_execution(self):
        self.calls.append(("continue", threading.get_ident()))
        self.data["state"] = "running"

    def evaluate(self, expression):
        self.calls.append(("evaluate", expression))
        return "0x1230 <board>"

    def read_memory(self, address, size):
        self.calls.append(("read", address, size))
        return b"ABCDEFGH"[:size]

    def write_memory(self, address, data):
        self.calls.append(("write", address, data))

    def execute_console(self, command):
        self.calls.append(("console", command))

    def add_rule(self, **config):
        self.calls.append(("rule", config))

    def update_rule(self, rule_id, **config):
        self.calls.append(("update", rule_id, config))

    def runtime_to_static(self, address, base):
        self.calls.append(("map-back", address, base))
        return 0x401230


class TestRuntimeDialogs(unittest.TestCase):
    """Validate user-entered connection, binding and breakpoint configuration."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_qapp()

    def test_connection_modes_validate_only_active_fields(self):
        dialog = RuntimeConnectionDialog("/games/snake")
        dialog.args.setText('--level "Ice caves"')
        dialog.env.setPlainText("LEVEL=3\nPLAYER=A B")
        method, config = dialog.configuration()
        self.assertEqual(method, "launch")
        self.assertEqual(config["args"], ["--level", "Ice caves"])
        self.assertEqual(config["env"], {"LEVEL": "3", "PLAYER": "A B"})
        dialog.env.setPlainText("BROKEN")
        with self.assertRaisesRegex(ValueError, "NAME=value"):
            dialog.configuration()
        dialog.mode.setCurrentIndex(dialog.mode.findData("attach"))
        dialog.pid.setValue(321)
        self.assertFalse(dialog.env.isEnabled())
        self.assertTrue(dialog.pid.isEnabled())
        self.assertEqual(dialog.configuration(), ("attach", {"pid": 321, "executable": "/games/snake"}))
        dialog.mode.setCurrentIndex(dialog.mode.findData("remote"))
        dialog.endpoint.clear()
        with self.assertRaisesRegex(ValueError, "endpoint"):
            dialog.configuration()
        dialog.endpoint.setText("localhost:5432")
        self.assertEqual(dialog.configuration()[0], "connect_remote")
        dialog.close()

    def test_invalid_launch_does_not_accept(self):
        dialog = RuntimeConnectionDialog()
        dialog._accept()
        self.assertEqual(dialog.result(), QDialog.DialogCode.Rejected)
        self.assertIn("executable", dialog.error.text())
        dialog.executable.setText("/game")
        dialog.args.setText('"unterminated')
        dialog._accept()
        self.assertEqual(dialog.result(), QDialog.DialogCode.Rejected)
        dialog.close()

    def test_rule_preview_and_clamp_validation(self):
        runtime: Any = _RuntimeDouble()
        dialog = RuntimeRuleDialog(runtime, "score", "Score", "clamp", "game_tick", "Resolved from the selected global")
        self.assertFalse(dialog.buttons.button(QDialogButtonBox.StandardButton.Ok).isEnabled())
        dialog.value.setText("100")
        self.assertTrue(dialog.buttons.button(QDialogButtonBox.StandardButton.Ok).isEnabled())
        self.assertIn("set variable (score) = (100)", dialog.preview.toPlainText())
        self.assertEqual(dialog.configuration()["trigger"], "game_tick")
        dialog.mode.setCurrentIndex(dialog.mode.findData("set"))
        self.assertFalse(dialog.trigger.isEnabled())
        self.assertEqual(dialog.preview.toPlainText(), "set variable score = 100")
        dialog.mode.setCurrentIndex(dialog.mode.findData("custom"))
        self.assertFalse(dialog.buttons.button(QDialogButtonBox.StandardButton.Ok).isEnabled())
        dialog.commands.setPlainText('printf "tick\\n"\ncontinue')
        self.assertEqual(dialog.preview.toPlainText().count("continue"), 1)
        self.assertEqual(dialog.configuration()["commands"], ['printf "tick\\n"', "continue"])
        dialog.close()

    def test_backend_preview_error_is_rendered_in_dialog(self):
        runtime: Any = _RuntimeDouble()
        runtime.preview_rule = MagicMock(side_effect=RuntimeErrorBase("Invalid expression"))
        dialog = RuntimeRuleDialog(runtime, "score")
        self.assertEqual(dialog.error.text(), "Invalid expression")
        self.assertFalse(dialog.buttons.button(QDialogButtonBox.StandardButton.Ok).isEnabled())
        dialog.close()

    def test_breakpoint_kind_and_condition(self):
        dialog = RuntimeBreakpointDialog()
        dialog.location.setText("game_tick")
        dialog.condition.setText("score > 10")
        dialog.temporary.setChecked(True)
        self.assertTrue(dialog.configuration()["temporary"])
        dialog.kind.setCurrentIndex(dialog.kind.findData("write"))
        dialog.location.setText("*(int*)0x1234")
        self.assertFalse(dialog.temporary.isEnabled())
        self.assertEqual(
            dialog.configuration(),
            {"kind": "write", "location": "*(int*)0x1234", "condition": "score > 10", "temporary": False},
        )
        dialog.close()


class TestRuntimeView(unittest.TestCase):
    """Exercise runtime controls, asynchronous completions and session guards."""

    def setUp(self):
        self.app = create_qapp()
        self.runtime: Any = _RuntimeDouble()
        self.instance: Any = SimpleNamespace(project=SimpleNamespace(am_obj=None))
        self.workspace: Any = SimpleNamespace(runtime=self.runtime, view_manager=MagicMock(), jump_to=MagicMock())
        self.view = RuntimeView(self.workspace, "right", self.instance)
        self.view.resize(1150, 800)
        self.view.show()

    def tearDown(self):
        self._drain()
        self.view.close()
        self.assertEqual(self.runtime.callbacks, [])

    def _drain(self):
        deadline = time.monotonic() + 3
        while self.view._pending and time.monotonic() < deadline:
            QTest.qWait(10)
        self.assertEqual(self.view._pending, 0)
        QTest.qWait(5)

    def _stop(self):
        self.runtime.data.update(state="stopped", executable="/game", pid=123)
        self.view.refresh()

    def test_control_states_and_worker_dispatch(self):
        self.assertTrue(self.view.connect_button.isEnabled())
        self.assertFalse(self.view.continue_button.isEnabled())
        self._stop()
        self.assertFalse(self.view.connect_button.isEnabled())
        self.assertTrue(self.view.continue_button.isEnabled())
        self.assertTrue(self.view.add_rule_button.isEnabled())
        self.assertFalse(self.view.snapshot_hint.isVisible())
        self.assertEqual(self.view.target_label.toolTip(), "/game")
        self.assertTrue(self.view.target_label.text().startswith("game · PID"))
        QTest.mouseClick(self.view.continue_button, Qt.MouseButton.LeftButton)
        self._drain()
        self.assertEqual(self.view.state_label.text(), "RUNNING")
        self.assertTrue(self.view.snapshot_hint.isVisible())
        self.assertIn("Last paused snapshot", self.view.snapshot_hint.text())
        self.assertTrue(self.view.pause_button.isEnabled())
        self.assertFalse(self.view.write_memory_button.isEnabled())
        self.assertNotEqual(self.runtime.calls[0][1], threading.get_ident())

    def test_detached_ready_state_can_connect_to_another_target(self):
        self.runtime.data["state"] = "ready"
        self.view.refresh()
        self.assertTrue(self.view.connect_button.isEnabled())
        self.assertFalse(self.view.stop_button.isEnabled())
        self.assertFalse(self.view.detach_button.isEnabled())
        self.assertFalse(self.view.add_rule_button.isEnabled())

    def test_worker_error_is_visible_and_does_not_wedge_controls(self):
        self._stop()
        self.view.submit("missing_backend_method")
        self._drain()
        self.assertIn("missing_backend_method", self.view.error_label.text())
        self.assertTrue(self.view.error_label.isVisible())
        self.assertTrue(self.view.continue_button.isEnabled())

    def test_pending_operations_do_not_reenable_controls_early(self):
        self._stop()
        first, second = threading.Event(), threading.Event()
        self.view._call(lambda: first.wait(2), "first")
        self.view._call(lambda: second.wait(2), "second")
        self.assertEqual(self.view._pending, 2)
        first.set()
        deadline = time.monotonic() + 1
        while self.view._pending == 2 and time.monotonic() < deadline:
            QTest.qWait(10)
        self.assertEqual(self.view._pending, 1)
        self.assertFalse(self.view.continue_button.isEnabled())
        second.set()
        self._drain()
        self.assertTrue(self.view.continue_button.isEnabled())

    def test_live_memory_expression_resolves_and_formats_actual_bytes(self):
        self._stop()
        self.view.memory_address.setText("&board")
        self.view.memory_size.setValue(8)
        self.view._read_memory()
        self._drain()
        self.assertIn(("evaluate", "&board"), self.runtime.calls)
        self.assertIn(("read", 0x1230, 8), self.runtime.calls)
        text = self.view.memory_text.toPlainText()
        self.assertIn("0000000000001230", text)
        self.assertIn("41 42 43 44 45 46 47 48", text)
        self.assertIn("ABCDEFGH", text)
        with patch("angrmanagement.ui.views.runtime_view.QInputDialog.getText", return_value=("01 02", True)):
            self.view._write_memory()
        self._drain()
        self.assertIn(("write", 0x1230, b"\x01\x02"), self.runtime.calls)

    def test_live_rules_preserve_selection_and_show_history_and_script(self):
        self._stop()
        self.runtime.data["rules"] = [
            {
                "id": "r1",
                "label": "Health",
                "expression": "health",
                "mode": "clamp",
                "value": "100",
                "enabled": True,
                "last_value": "100",
                "samples": [{"value": "80"}, {"value": "100"}],
                "generated_script": "commands 1\nsilent\ncontinue\nend",
            }
        ]
        self.view.refresh()
        self.view.rules_table.selectRow(0)
        self.assertEqual(self.view.chart._values, [80.0, 100.0])
        self.assertEqual(self.view.rule_preview.toPlainText(), "commands 1\nsilent\ncontinue\nend")
        self.view.refresh()
        selected = self.view._selected_rule()
        assert selected is not None
        self.assertEqual(selected["id"], "r1")
        self.view._toggle_rule()
        self._drain()
        self.assertIn(("update", "r1", {"enabled": False}), self.runtime.calls)
        self.runtime.data["rules"][0]["id"] = "r2"
        self.view.refresh()
        self.assertIsNone(self.view._selected_rule())

    def test_resolved_binding_is_reviewed_on_gui_thread(self):
        self._stop()
        threads = []

        def resolve(runtime):
            self.assertIs(runtime, self.runtime)
            threads.append(threading.get_ident())
            return {"expression": "*(int*)0x1234", "label": "Score", "trigger": None, "note": "A global"}

        with patch.object(self.view, "open_binding") as open_binding:
            self.view.resolve_binding(resolve, mode="clamp")
            self._drain()
            open_binding.assert_called_once_with(
                expression="*(int*)0x1234",
                label="Score",
                trigger=None,
                note="A global",
                mode="clamp",
                expected_generation=0,
            )
        self.assertNotEqual(threads[0], threading.get_ident())

    def test_set_once_and_monitor_dispatch_differ(self):
        self._stop()
        config = {
            "label": "Score",
            "expression": "score",
            "mode": "set",
            "value": "100",
            "trigger": None,
            "commands": None,
        }
        with patch("angrmanagement.ui.views.runtime_view.RuntimeRuleDialog") as dialog:
            dialog.return_value.exec.return_value = QDialog.DialogCode.Accepted
            dialog.return_value.configuration.return_value = config
            self.view.open_binding("score", mode="set")
            self._drain()
            self.assertIn(("console", "set variable score = 100"), self.runtime.calls)
            config["mode"] = "monitor"
            config["value"] = None
            self.view.open_binding("score")
            self._drain()
            self.assertIn(("rule", config), self.runtime.calls)

    def test_pc_navigation_uses_runtime_mapping(self):
        self._stop()
        self.instance.project.am_obj = SimpleNamespace(
            loader=SimpleNamespace(main_object=SimpleNamespace(mapped_base=0x400000, binary="/game"))
        )
        self.runtime.data["frame"] = {"addr": 0x7FFFF1230, "func": "tick"}
        self.view.refresh()
        self.view._show_pc()
        self._drain()
        self.assertIn(("map-back", 0x7FFFF1230, 0x400000), self.runtime.calls)
        self.workspace.jump_to.assert_called_once_with(0x401230)

    def test_background_events_are_marshaled_and_console_text_is_preserved(self):
        self.runtime.data["output"] = [{"text": "Game ready\n", "channel": "target"}]
        self.view.console_input.setText("info locals")
        worker = threading.Thread(target=lambda: self.runtime.callbacks[0]("output", {"text": "Game ready\n"}))
        worker.start()
        worker.join()
        deadline = time.monotonic() + 3
        while not self.view.console_output.toPlainText() and time.monotonic() < deadline:
            QTest.qWait(20)
        self.assertEqual(self.view.console_output.toPlainText(), "Game ready\n")
        self.assertEqual(self.view.console_input.text(), "info locals")

    def test_inspector_selection_and_register_write(self):
        self._stop()
        self.runtime.data.update(
            threads=[{"id": "2", "state": "stopped", "frame": {"func": "tick"}}],
            frames=[{"level": 0, "func": "tick", "addr": 0x1234}],
            registers=[{"name": "rax", "value": "0x1"}, {"name": "rbx", "value": "0x2"}],
        )
        self.runtime.select_thread = MagicMock()
        self.runtime.select_frame = MagicMock()
        self.runtime.write_register = MagicMock()
        self.view.refresh()
        self.view._select_thread(0, 0)
        self._drain()
        self.runtime.select_thread.assert_called_once_with("2")
        self.view._select_frame(0, 0)
        self._drain()
        self.runtime.select_frame.assert_called_once_with(0)
        self.view.register_filter.setText("rax")
        self.assertFalse(self.view.registers_table.isRowHidden(0))
        self.assertTrue(self.view.registers_table.isRowHidden(1))
        with patch("angrmanagement.ui.views.runtime_view.QInputDialog.getText", return_value=("42", True)):
            self.view._edit_register(0, 1)
        self._drain()
        self.runtime.write_register.assert_called_once_with("rax", "42")

    def test_breakpoint_toggle_and_removal_use_selected_identity(self):
        self._stop()
        self.runtime.data["breakpoints"] = [{"number": "7", "enabled": "y", "type": "breakpoint", "addr": "0x1234"}]
        self.runtime.enable_breakpoint = MagicMock()
        self.runtime.remove_breakpoint = MagicMock()
        self.view.refresh()
        self.view.breakpoints_table.selectRow(0)
        self.view._toggle_breakpoint()
        self._drain()
        self.runtime.enable_breakpoint.assert_called_once_with("7", enabled=False)
        self.view._remove_breakpoint()
        self._drain()
        self.runtime.remove_breakpoint.assert_called_once_with("7")

    def test_module_mapping_requires_explicit_analysis_base_for_library(self):
        self._stop()
        self.instance.project.am_obj = SimpleNamespace(
            loader=SimpleNamespace(main_object=SimpleNamespace(mapped_base=0x400000, binary="/game"))
        )
        self.runtime.data["modules"] = [
            {
                "id": "libgame",
                "path": "/lib/game.so",
                "start": 0xA000,
                "end": 0xF000,
                "load_bias": 0xA000,
                "linked_base": 0,
            }
        ]
        self.runtime.static_to_runtime = MagicMock(return_value=0xA123)
        self.view.refresh()
        self.view.modules_table.selectRow(0)
        self.view.static_address.setText("0x123")
        self.view._map_address()
        self.assertIn("analysis base", self.view.error_label.text())
        self.runtime.static_to_runtime.assert_not_called()
        self.view.module_static_base.setText("0")
        self.view._map_address()
        self._drain()
        self.runtime.static_to_runtime.assert_called_once_with(0x123, 0, module_id="libgame")
        self.assertIn("0xa123", self.view.mapping_label.text())

    def test_mapped_range_opens_memory_and_unreadable_range_is_rejected(self):
        self._stop()
        self.runtime.data["memory_maps"] = [
            {"start": 0x1230, "end": 0x1240, "permissions": "rw-p", "path": "[heap]"},
            {"start": 0x2000, "end": 0x3000, "permissions": "---p", "path": ""},
        ]
        self.view.refresh()
        self.view._open_mapping(0, 0)
        self._drain()
        self.assertEqual(self.view.memory_address.text(), "0x1230")
        self.assertEqual(self.view.memory_size.value(), 16)
        self.assertIs(self.view.inspectors.currentWidget(), self.view.memory_panel)
        self.assertIn(("read", 0x1230, 16), self.runtime.calls)
        self.view._open_mapping(1, 0)
        self.assertIn("not readable", self.view.error_label.text())

    def test_upper_half_address_mapping_renders_and_retains_selection(self):
        self._stop()
        address = 0xFFFFFFFFFF600000
        self.runtime.data["memory_maps"] = [
            {"start": address, "end": address + 4096, "permissions": "--xp", "path": "[vsyscall]"},
        ]
        self.view.refresh()
        self.view.mappings_table.selectRow(0)
        self.view.refresh()
        self.assertEqual(self.view._selected_id(self.view.mappings_table), hex(address))
        self.view._open_mapping(0, 0)
        self.assertIn("not readable", self.view.error_label.text())

    def test_custom_hook_edit_preserves_rule_identity(self):
        self._stop()
        self.runtime.data["rules"] = [
            {
                "id": "r9",
                "label": "Log tick",
                "expression": "score",
                "mode": "custom",
                "enabled": True,
                "trigger": "tick",
                "commands": ['printf "old"'],
            }
        ]
        self.view.refresh()
        self.view.rules_table.selectRow(0)
        self.assertTrue(self.view.edit_rule_button.isEnabled())
        with patch("angrmanagement.ui.views.runtime_view.RuntimeRuleDialog") as dialog:
            dialog.return_value.exec.return_value = QDialog.DialogCode.Accepted
            dialog.return_value.configuration.return_value = {"commands": ['printf "new"']}
            self.view._edit_rule()
            self._drain()
        self.assertIn(("update", "r9", {"commands": ['printf "new"']}), self.runtime.calls)

    def test_connect_dialog_does_not_replace_new_mcp_target(self):
        with patch("angrmanagement.ui.views.runtime_view.RuntimeConnectionDialog") as dialog:

            def accepted():
                self.runtime.data.update(generation=1, state="stopped")
                return QDialog.DialogCode.Accepted

            dialog.return_value.exec.side_effect = accepted
            dialog.return_value.configuration.return_value = ("launch", {"executable": "/game"})
            self.view._connect()
            self._drain()
        self.assertIn("session changed", self.view.error_label.text())
        self.assertEqual(self.runtime.data["state"], "stopped")

    def test_binding_resolved_for_previous_generation_is_not_offered(self):
        self._stop()
        self.runtime.data["generation"] = 2
        with patch("angrmanagement.ui.views.runtime_view.RuntimeRuleDialog") as dialog:
            self.view.open_binding("*(int*)0x1234", expected_generation=1)
            dialog.assert_not_called()
        self.assertIn("session changed", self.view.error_label.text())

    def test_target_input_is_separate_from_gdb_commands(self):
        self._stop()
        self.runtime.data["capabilities"] = {"input": True}
        self.runtime.data["state"] = "running"
        self.view.refresh()
        self.assertTrue(self.view.target_input.isEnabled())
        self.assertFalse(self.view.console_input.isEnabled())
        self.view.target_input.setText("wasd")
        self.view._send_input()
        self._drain()
        self.assertIn(("input", "wasd\n"), self.runtime.calls)

    def test_modal_binding_rejects_a_restarted_session(self):
        self._stop()
        config = {
            "label": "Score",
            "expression": "*(int*)0x1234",
            "mode": "set",
            "value": "100",
            "trigger": None,
            "commands": None,
        }
        with patch("angrmanagement.ui.views.runtime_view.RuntimeRuleDialog") as dialog:

            def accepted():
                self.runtime.data["generation"] = 1
                return QDialog.DialogCode.Accepted

            dialog.return_value.exec.side_effect = accepted
            dialog.return_value.configuration.return_value = config
            self.view.open_binding("*(int*)0x1234", mode="set")
            self._drain()
        self.assertIn("session changed", self.view.error_label.text())
        self.assertFalse(any(call[0] == "console" for call in self.runtime.calls))

    def test_switching_a_scoped_binding_to_set_requires_its_pc(self):
        self._stop()
        self.runtime.data["frame"] = {"addr": 0x9876}
        config = {
            "label": "Counter",
            "expression": "$rax",
            "mode": "set",
            "value": "100",
            "trigger": "*0x1234",
            "commands": None,
        }
        with patch("angrmanagement.ui.views.runtime_view.RuntimeRuleDialog") as dialog:
            dialog.return_value.exec.return_value = QDialog.DialogCode.Accepted
            dialog.return_value.configuration.return_value = config
            self.view.open_binding("$rax", mode="monitor", trigger="*0x1234")
            self._drain()
        self.assertIn("stopped PC changed", self.view.error_label.text())
        self.assertFalse(any(call[0] == "console" for call in self.runtime.calls))

    def test_same_pc_in_another_thread_does_not_accept_delayed_write(self):
        self._stop()
        self.runtime.data.update(selected_thread="1", frame={"addr": 0x1234, "level": 0})
        config = {
            "label": "Counter",
            "expression": "$rax",
            "mode": "set",
            "value": "100",
            "trigger": "*0x1234",
            "commands": None,
        }
        with patch("angrmanagement.ui.views.runtime_view.RuntimeRuleDialog") as dialog:

            def accepted():
                self.runtime.data["selected_thread"] = "2"
                return QDialog.DialogCode.Accepted

            dialog.return_value.exec.side_effect = accepted
            dialog.return_value.configuration.return_value = config
            self.view.open_binding("$rax", mode="set", trigger="*0x1234")
            self._drain()
        self.assertIn("selected thread changed", self.view.error_label.text())
        self.assertFalse(any(call[0] == "console" for call in self.runtime.calls))

    def test_status_badge_follows_palette_changes(self):
        self._stop()
        palette = QPalette(self.view.palette())
        palette.setColor(QPalette.ColorRole.Highlight, QColor("#9a38b8"))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
        self.view.setPalette(palette)
        QTest.qWait(5)
        self.assertEqual(self.view.state_label.palette().color(QPalette.ColorRole.Window), QColor("#9a38b8"))
        self.assertEqual(self.view.state_label.palette().color(QPalette.ColorRole.WindowText), QColor("#ffffff"))

    def test_history_ignores_non_numeric_values(self):
        chart = RuntimeHistoryChart()
        chart.set_samples([{"value": "1"}, {"value": "0x10"}, {"value": "nan"}, {"value": "{x = 2}"}, {"value": "2.5"}])
        self.assertEqual(chart._values, [1.0, 16.0, 2.5])
        chart.close()
