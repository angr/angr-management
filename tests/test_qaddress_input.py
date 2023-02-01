import os
import sys
import threading
import unittest

import angr
from angr import load_shellcode
from common import start_main_window_and_event_loop, test_location
from PySide6.QtTest import QTest

from angrmanagement.logic.threads import gui_thread_schedule
from angrmanagement.ui.widgets.qaddress_input import QAddressInput


class TestQaddressInput(unittest.TestCase):
    def setUp(self):
        self.event = threading.Event()
        _, self.main = start_main_window_and_event_loop(self.event)

    def tearDown(self) -> None:
        self.event.set()
        del self.main

    def _test_address_conversion(self):
        main = self.main
        main.workspace.main_instance.project.am_obj = load_shellcode(b"X", "amd64")
        main.workspace.main_instance.project.kb.functions.function(addr=0x1234, name="foo", create=True)

        obj = QAddressInput(None, main.workspace.main_instance)

        obj.setText("")
        QTest.keyClicks(obj, "4321")
        self.assertEqual(obj.target, 0x4321)

        obj.setText("")
        QTest.keyClicks(obj, "foo")
        self.assertEqual(obj.target, 0x1234)

        obj.setText("")
        QTest.keyClicks(obj, "12x3")
        self.assertIsNone(obj.target)

    def test_address_conversion(self):
        gui_thread_schedule(self._test_address_conversion)

    def _test_function_name(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        main = self.main
        main.workspace.main_instance.project.am_obj = proj

        cfg = proj.analyses.CFG()
        obj = QAddressInput(None, main.workspace.main_instance)

        obj.setText("")
        QTest.keyClicks(obj, "main")
        self.assertEqual(obj.target, cfg.kb.functions["main"].addr)

        obj.setText("")
        QTest.keyClicks(obj, "main_1")
        self.assertIsNone(obj.target)

    def test_function_name(self):
        gui_thread_schedule(self._test_function_name)


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
