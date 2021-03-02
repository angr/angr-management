from PySide2.QtTest import QTest

from angrmanagement.ui.main_window import MainWindow
from angr import load_shellcode

from angrmanagement.ui.widgets.qaddress_input import QAddressInput
from common import setUp

def test_address_conversion():
    main = MainWindow(show=False)
    main.workspace.instance.set_project(load_shellcode(b'X', 'amd64'))
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
