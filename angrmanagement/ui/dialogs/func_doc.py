from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, \
    QGridLayout, QRadioButton, QGroupBox, QScrollArea, QWidget
from PySide2.QtGui import QTextOption
from pyqodeng.core.api import CodeEdit
from pyqodeng.core.modes import CaretLineHighlighterMode, PygmentsSyntaxHighlighter, AutoIndentMode
from ...data.instance import Instance


class FuncDocDialog(QDialog):
    """
    Provide templates of FuncDocDialog function.
    """
    def __init__(self, instance: Instance, addr=None, name="", doc="", url="", ftype="", parent=None):
        super().__init__(parent)

        # initialization

        self.instance = instance
        self.state = None  # output
        self._addr = addr
        self._name = name
        self._doc = doc
        self._url = url
        self._ftype = ftype
        self._function_box = None
        self._ok_button = None
        self.setWindowTitle('Function Documentation')
        self.main_layout = QVBoxLayout()
        self._init_widgets()
        self.setLayout(self.main_layout)

    def _init_widgets(self):
        layout = QGridLayout()
        row = 0

        # validation_failures = set()
        addr = hex(self._addr)
        address_label = QLabel(self)
        address_label.setText(f"Function at address {addr}: {self._name}")

        layout.addWidget(address_label)

        type_label = QLabel(self)
        type_label.setText(f"Type: {self._ftype}")

        layout.addWidget(type_label)


        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        widget = QWidget()
        scroll_area.setWidget(widget)
        layout_scroll = QVBoxLayout(widget)

        doc_label = QLabel(self)
        doc_label.setText(self._doc)

        url_label = QLabel(self)
        url_label.setText(self._url)

        layout_scroll.addWidget(doc_label)
        layout_scroll.addWidget(url_label)
        layout.addWidget(scroll_area)

        ok_button = QPushButton(self)
        ok_button.setText('Ok')

        def do_ok():
            self.close()

        ok_button.clicked.connect(do_ok)

        self.main_layout.addLayout(layout)
        self.main_layout.addWidget(ok_button)
