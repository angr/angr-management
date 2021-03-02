import os

from PySide2.QtTest import QTest

from angrmanagement.ui.main_window import MainWindow
import angr
from angr import load_shellcode

from angrmanagement.ui.widgets.qaddress_input import QAddressInput
from common import setUp, test_location




def test_address_conversion():
    main = MainWindow(show=False)
    main.workspace.instance.project = load_shellcode(b'X', 'amd64')
    main.workspace.instance.project.kb.functions.function(addr=0x1234, name='foo', create=True)

    obj = QAddressInput(None, main.workspace)

    obj.setText("")
    QTest.keyClicks(obj, "4321")
    assert obj.target == 0x4321

    obj.setText("")
    QTest.keyClicks(obj, "foo")
    assert obj.target == 0x1234

    obj.setText("")
    QTest.keyClicks(obj, "12x3")
    assert obj.target is None


def test_function_name():
    proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
    main = MainWindow(show=False)
    main.workspace.instance.project = proj

    cfg = proj.analyses.CFG()
    obj = QAddressInput(None, main.workspace)

    obj.setText("")
    QTest.keyClicks(obj, "main")
    assert obj.target == cfg.kb.functions['main'].addr

    obj.setText("")
    QTest.keyClicks(obj, "main_1")
    assert obj.target is None


if __name__ == "__main__":
    setUp()
    test_address_conversion()
    test_function_name()
