import os
import sys
import unittest

from PySide6.QtTest import QTest

from angrmanagement.ui.main_window import MainWindow
import angr
from angr import load_shellcode

from angrmanagement.ui.widgets.qaddress_input import QAddressInput
from common import setUp, test_location


class TestQaddressInput(unittest.TestCase):
    def setUp(self):
        setUp()

    def test_address_conversion(self):
        main = MainWindow(show=False)
        main.workspace.instance.project = load_shellcode(b'X', 'amd64')
        main.workspace.instance.project.kb.functions.function(addr=0x1234, name='foo', create=True)

        obj = QAddressInput(None, main.workspace)

        obj.setText("")
        QTest.keyClicks(obj, "4321")
        self.assertEqual(obj.target, 0x4321)

        obj.setText("")
        QTest.keyClicks(obj, "foo")
        self.assertEqual(obj.target, 0x1234)

        obj.setText("")
        QTest.keyClicks(obj, "12x3")
        self.assertIsNone(obj.target)


    def test_function_name(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        main = MainWindow(show=False)
        main.workspace.instance.project = proj

        cfg = proj.analyses.CFG()
        obj = QAddressInput(None, main.workspace)

        obj.setText("")
        QTest.keyClicks(obj, "main")
        self.assertEqual(obj.target, cfg.kb.functions['main'].addr)

        obj.setText("")
        QTest.keyClicks(obj, "main_1")
        self.assertIsNone(obj.target)


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
