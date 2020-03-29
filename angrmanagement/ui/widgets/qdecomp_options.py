
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QWidget, QVBoxLayout, QLineEdit, QTreeWidget, QTreeWidgetItem, QPushButton

from angr.analyses.decompiler.decompilation_options import DecompilationOption, options as dec_options
from angr.analyses.decompiler.optimization_passes import get_optimization_passes


class OptionType:
    OPTION = 1
    OPTIMIZATION_PASS = 2


class QDecompilationOption(QTreeWidgetItem):
    def __init__(self, parent, option, type_: int):
        super().__init__(parent)
        self.option = option
        self.type = type_

        if self.type == OptionType.OPTIMIZATION_PASS:
            self.setText(0, option.__name__)
        elif self.type == OptionType.OPTION:
            self.setText(0, option.name)
            self.setToolTip(0, option.description)
        else:
            raise NotImplementedError("Unsupported option type %s." % self.type_)

        self.setFlags(self.flags() | Qt.ItemIsUserCheckable)
        self.setCheckState(0, Qt.Checked)


class QDecompilationOptions(QWidget):
    def __init__(self, code_view, instance, options=None, passes=None):
        super().__init__()

        self._code_view = code_view
        self._instance = instance
        self._options = options
        self._opti_passes = passes

        # widgets
        self._search_box = None  # type:QLineEdit
        self._treewidget = None  # type:QTreeWidget
        self._apply_btn = None  # type:QPushButton

        self._qoptions = [ ]
        self._qoptipasses = [ ]

        self._init_widgets()

        self.reload()

    def reload(self, force=False):
        if force or self._options is None:
            self._options = self.get_default_options()

        if force or self._opti_passes is None:
            if self._instance.project is not None:
                self._opti_passes = self.get_default_passes()
            else:
                self._opti_passes = []

        self._reload_options()

    @property
    def selected_passes(self):
        selected = [ ]
        for item in self._qoptipasses:
            if item.checkState(0):
                selected.append(item.option)
        return selected

    @property
    def option_and_values(self):
        ov = [ ]
        for item in self._qoptions:
            if item.checkState(0):
                ov.append((item.option, True))
            else:
                ov.append((item.option, False))
        return ov

    @property
    def options(self):
        return self._options

    @options.setter
    def options(self, v):
        self._options = v
        self._reload_options()

    def get_default_options(self):
        return dec_options

    def get_default_passes(self):
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
        self._qoptipasses.clear()

        categories = { }

        # populate the tree widget with new options
        for option in sorted(self._options, key=lambda x: x.name):
            if option.category in categories:
                category = categories[option.category]
            else:
                category = QTreeWidgetItem(self._treewidget, [option.category])

            w = QDecompilationOption(category, option, OptionType.OPTION)
            self._qoptions.append(w)

        passes_category = QTreeWidgetItem(self._treewidget, ["Optimization Passes"])
        categories['passes'] = passes_category

        for pass_ in sorted(self._opti_passes, key=lambda x: x.__name__):
            w = QDecompilationOption(passes_category, pass_, OptionType.OPTIMIZATION_PASS)
            self._qoptipasses.append(w)

        # expand all
        self._treewidget.expandAll()
