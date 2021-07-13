from PySide2.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, \
    QGridLayout, QScrollArea, QWidget
from ...data.instance import Instance


class FuncDocDialog(QDialog):
    """
    Provide templates of FuncDocDialog function.
    """
    def __init__(self, instance: Instance, addr=None, name="", doc_tuple=None, parent=None):
        super().__init__(parent)

        # initialization

        self.instance = instance
        self._addr = addr
        self._name = name
        self._doc = doc_tuple[0]
        self._url = doc_tuple[1]
        self._ftype = doc_tuple[2]
        self._ok_button = None
        self.setWindowTitle('Function Documentation')
        self.main_layout = QVBoxLayout()
        self._init_widgets()
        self.setLayout(self.main_layout)

    def _ok_method(self):
        self.close()

    def _init_widgets(self):
        layout = QGridLayout()

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

        self._ok_button = QPushButton('Ok', self)
        self._ok_button.clicked.connect(self._ok_method)

        self.main_layout.addLayout(layout)
        self.main_layout.addWidget(self._ok_button)
