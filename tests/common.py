from PySide2.QtWidgets import QApplication

from angrmanagement.config import Conf

app = None

def setUp():
    global app
    if app is None:
        app = QApplication([])
        Conf.init_font_config()

