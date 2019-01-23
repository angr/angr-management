
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QWidget, QVBoxLayout, QLineEdit, QTreeWidget, QTreeWidgetItem, QPushButton

from angr.analyses.decompiler.optimization_passes import get_optimization_passes


class QDecompilationOption(QTreeWidgetItem):
    def __init__(self, parent, option):
        super().__init__(parent)
        self.option = option
        self.setText(0, option.__name__)
        self.setFlags(self.flags() | Qt.ItemIsUserCheckable)
        self.setCheckState(0, Qt.Checked)


class QDecompilationOptions(QWidget):
    def __init__(self, code_view, instance, options=None):
        super().__init__()

        self._code_view = code_view
        self._instance = instance
        self._options = options
        if self._options is None:
            if instance.project is not None:
                self._options = self.get_default_options()
            else:
                self._options = [ ]

        # widgets
        self._search_box = None  # type:QLineEdit
        self._treewidget = None  # type:QTreeWidget
        self._apply_btn = None  # type:QPushButton

        self._qoptions = [ ]

        self._init_widgets()

        self._reload_options()

    @property
    def selected_options(self):
        selected = [ ]
        for item in self._qoptions:
            if item.checkState(0):
                selected.append(item.option)
        return selected

    @property
    def options(self):
        return self._options

    @options.setter
    def options(self, v):
        self._options = v
        self._reload_options()

    def get_default_options(self):
        return get_optimization_passes(self._instance.project.arch, self._instance.project.simos.name)

    def _init_widgets(self):

        # search box
        self._search_box = QLineEdit()

        # tree view
        self._treewidget = QTreeWidget()
        self._treewidget.setHeaderHidden(True)

        # refresh button
        self._apply_btn = QPushButton("Apply")
        self._apply_btn.clicked.connect(self._code_view.decompile)

        layout = QVBoxLayout()
        layout.addWidget(self._search_box)
        layout.addWidget(self._treewidget)
        layout.addWidget(self._apply_btn)

        self.setLayout(layout)

    def _reload_options(self):

        self._treewidget.clear()
        self._qoptions.clear()

        # populate the tree widget with new options
        for option in sorted(self._options, key=lambda x: x.__name__):
            w = QDecompilationOption(self._treewidget, option)
            self._qoptions.append(w)
