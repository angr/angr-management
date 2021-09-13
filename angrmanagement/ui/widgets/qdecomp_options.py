from typing import Optional

from PySide2.QtCore import Qt
from PySide2.QtWidgets import QWidget, QVBoxLayout, QLineEdit, QTreeWidget, QTreeWidgetItem, QPushButton

from angr.analyses.decompiler.decompilation_options import options as dec_options
from angr.analyses.decompiler.optimization_passes import get_optimization_passes, get_default_optimization_passes
from angr.analyses.decompiler.peephole_optimizations import EXPR_OPTS, STMT_OPTS


class OptionType:
    OPTION = 1
    OPTIMIZATION_PASS = 2
    PEEPHOLE_OPTIMIZATION = 3


class QDecompilationOption(QTreeWidgetItem):
    def __init__(self, parent, option, type_: int, enabled=True):
        super().__init__(parent)
        self.option = option
        self.type = type_

        if self.type == OptionType.OPTIMIZATION_PASS:
            self.setText(0, option.__name__)
        elif self.type == OptionType.OPTION:
            self.setText(0, option.name)
            self.setToolTip(0, option.description)
        elif self.type == OptionType.PEEPHOLE_OPTIMIZATION:
            self.setText(0, option.name)
            self.setToolTip(0, option.description)
        else:
            raise NotImplementedError("Unsupported option type %s." % self.type_)

        self.setFlags(self.flags() | Qt.ItemIsUserCheckable)
        if enabled:
            self.setCheckState(0, Qt.Checked)
        else:
            self.setCheckState(0, Qt.Unchecked)


class QDecompilationOptions(QWidget):
    def __init__(self, code_view, instance, options=None, passes=None, peephole_opts=None):
        super().__init__()

        self.dirty = True

        self._code_view = code_view
        self._instance = instance
        self._options = options
        self._opti_passes = passes
        self._peephole_opts = peephole_opts

        # widgets
        self._search_box = None  # type:QLineEdit
        self._treewidget = None  # type:QTreeWidget
        self._apply_btn = None  # type:QPushButton

        self._qoptions = [ ]
        self._qoptipasses = [ ]
        self._qpeephole_opts = [ ]

        self._init_widgets()

        self.reload()

    def reload(self, force=False):
        if force or self._options is None:
            self._options = self.get_default_options()

        if force or self._opti_passes is None:
            if not self._instance.project.am_none:
                self._opti_passes = self.get_all_passes()
            else:
                self._opti_passes = []

        if force or self._peephole_opts is None:
            self._peephole_opts = self.get_all_peephole_opts()

        self._reload_options()

    def _on_item_changed(self, item, _column):
        if getattr(item.option, 'clears_cache', True):
            self.dirty = True

    def _on_apply_pressed(self):
        if self.dirty:
            self.dirty = False
            # clear the cached version
            self._code_view.decompile(reset_cache=True)
        else:
            self._code_view.codegen.reapply_options(self.option_and_values)
            self._code_view.codegen.am_event()

    @property
    def selected_passes(self):
        selected = [ ]
        for item in self._qoptipasses:
            if item.checkState(0):
                selected.append(item.option)
        return selected

    @property
    def selected_peephole_opts(self):
        selected = []
        for item in self._qpeephole_opts:
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

    def get_default_options(self):  # pylint: disable=no-self-use
        return dec_options

    def get_default_passes(self):
        if self._instance is None or self._instance.project.am_none:
            return set()
        return get_default_optimization_passes(self._instance.project.arch, self._instance.project.simos.name)

    def get_all_passes(self):
        return get_optimization_passes(self._instance.project.arch, self._instance.project.simos.name)

    def get_default_peephole_opts(self):  # pylint: disable=no-self-use
        return STMT_OPTS + EXPR_OPTS

    def get_all_peephole_opts(self):  # pylint: disable=no-self-use
        return STMT_OPTS + EXPR_OPTS

    def _init_widgets(self):

        # search box
        self._search_box = QLineEdit()
        self._search_box.textChanged.connect(self._on_search_box_text_changed)

        # tree view
        self._treewidget = QTreeWidget()
        self._treewidget.setHeaderHidden(True)
        self._treewidget.itemChanged.connect(self._on_item_changed)

        # refresh button
        self._apply_btn = QPushButton("Apply")
        self._apply_btn.clicked.connect(self._on_apply_pressed)

        layout = QVBoxLayout()
        layout.addWidget(self._search_box)
        layout.addWidget(self._treewidget)
        layout.addWidget(self._apply_btn)

        self.setLayout(layout)

    def _reload_options(self, filter_by: Optional[str]=None):

        self._treewidget.clear()
        self._qoptions.clear()
        self._qoptipasses.clear()
        self._qpeephole_opts.clear()

        categories = { }

        # populate the tree widget with new options
        for option in sorted(self._options, key=lambda x: x.name):
            if filter_by:
                if not (filter_by in option.name or filter_by in option.category):
                    continue
            if option.category in categories:
                category = categories[option.category]
            else:
                category = QTreeWidgetItem(self._treewidget, [option.category])
                categories[option.category] = category

            w = QDecompilationOption(category, option, OptionType.OPTION, enabled=option.default_value)
            self._qoptions.append(w)

        passes_category = QTreeWidgetItem(self._treewidget, ["Optimization Passes"])
        categories['passes'] = passes_category

        default_passes = set(self.get_default_passes())
        for pass_ in self._opti_passes:
            if filter_by:
                if not filter_by in pass_.__name__:
                    continue
            w = QDecompilationOption(passes_category, pass_, OptionType.OPTIMIZATION_PASS,
                                     enabled=pass_ in default_passes)
            self._qoptipasses.append(w)

        po_category = QTreeWidgetItem(self._treewidget, ["Peephole Optimizations"])
        categories['peephole_opts'] = po_category

        default_peephole_opts = self.get_default_peephole_opts()
        for opt_ in self._peephole_opts:
            if filter_by:
                if not (filter_by in opt_.name or filter_by in opt_.description):
                    continue
            w = QDecompilationOption(po_category, opt_, OptionType.PEEPHOLE_OPTIMIZATION,
                                     enabled=opt_ in default_peephole_opts)
            self._qpeephole_opts.append(w)

        # expand all
        self._treewidget.expandAll()

    def _on_search_box_text_changed(self, text: str):
        self._reload_options(filter_by=text)
