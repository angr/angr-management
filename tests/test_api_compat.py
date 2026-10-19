"""
Names and call shapes that third-party code used before the presenters took the code over, and that still work.
"""

from __future__ import annotations

import contextlib
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from angrmanagement.data.signatures import BINDIFF_FILES_QUESTION, SignatureManager
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.disassembly import InfoDock
from angrmanagement.present import disasm as present_disasm
from angrmanagement.ui.dialogs.load_binary import LoadBinary
from angrmanagement.ui.views import disassembly_view


@contextlib.contextmanager
def ui_services(services):
    """Install ``services`` as GlobalInfo.ui_services for the block, then put the old ones back."""
    saved = GlobalInfo.ui_services
    GlobalInfo.ui_services = services
    try:
        yield services
    finally:
        GlobalInfo.ui_services = saved


class TestApiCompat(unittest.TestCase):
    """The old names and calls."""

    def test_infodock_takes_the_view_by_keyword(self):
        view = SimpleNamespace()
        infodock = InfoDock(disasm_view=view)
        assert infodock.owner is view and infodock.disasm_view is view
        infodock = InfoDock(view)
        assert infodock.owner is view and infodock.disasm_view is view
        owner = SimpleNamespace()
        infodock = InfoDock(owner, view)
        assert infodock.owner is owner and infodock.disasm_view is view
        with self.assertRaises(TypeError):
            InfoDock()

    def test_refresh_interval_still_importable_from_the_view_module(self):
        self.assertEqual(
            disassembly_view.MIN_OBJECTS_ADDED_REFRESH_INTERVAL, present_disasm.MIN_OBJECTS_ADDED_REFRESH_INTERVAL
        )

    def test_binary_loading_failed_tells_the_user(self):
        with ui_services(MagicMock()) as services:
            LoadBinary.binary_loading_failed("/tmp/a.out")
        self.assertEqual(
            services.message.call_args_list,
            [(("critical", "Failed to load binary", "angr failed to load binary /tmp/a.out."),)],
        )

    def test_select_bindiff_base_files_asks_the_user(self):
        manager = SignatureManager(MagicMock())
        with ui_services(MagicMock()) as services:
            services.pick_open_files.return_value = ["/tmp/libc.a"]
            self.assertEqual(manager.select_bindiff_base_files(), ["/tmp/libc.a"])
            services.pick_open_files.assert_called_once_with(*BINDIFF_FILES_QUESTION)
            services.pick_open_files.return_value = []
            self.assertIsNone(manager.select_bindiff_base_files())


if __name__ == "__main__":
    unittest.main()
