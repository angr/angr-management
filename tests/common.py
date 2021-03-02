import os

from PySide2.QtWidgets import QApplication

from angrmanagement.config import Conf


app = None

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

def setUp():
    global app
    if app is None:
        app = QApplication([])
        Conf.init_font_config()

