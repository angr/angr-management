from __future__ import annotations

from typing import TYPE_CHECKING

from angr.analyses.decompiler.decompilation_options import options as dec_options
from angr.analyses.decompiler.optimization_passes import get_default_optimization_passes, get_optimization_passes
from angr.analyses.decompiler.peephole_optimizations import EXPR_OPTS, MULTI_STMT_OPTS, STMT_OPTS
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QComboBox, QLineEdit, QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.views.code_view import CodeView


class OptionType:
    """
    An enum to determine what the .option field of a QDecompilationOption contains
    """

    OPTION = 1
    OPTIMIZATION_PASS = 2
    PEEPHOLE_OPTIMIZATION = 3


class QDecompilationOption(QTreeWidgetItem):
    """
    The UI entry for a single decompliation option. Get status with item.state.
    """

    def __init__(self, parent, option, type_: int, enabled: bool = True) -> None:
        super().__init__(parent)
        self.option = option
        self.type = type_

        # optional and may not exist
        self._combo_box = None

        if self.type in (OptionType.OPTIMIZATION_PASS, OptionType.OPTION, OptionType.PEEPHOLE_OPTIMIZATION):
            self.setText(0, option.NAME)
            self.setToolTip(0, option.DESCRIPTION)
        else:
            raise NotImplementedError(f"Unsupported option type {self.type_}.")

        # should make a dropdown option
        if (
            hasattr(self.option, "value_type")
            and not isinstance(self.option.value_type, bool)
            and self.option.candidate_values
        ):
            self._combo_box = QComboBox()
            self._combo_box.addItems(
                [self.option.default_value]
                + [c for c in self.option.candidate_values if c != self.option.default_value]
            )
            self._combo_box.setToolTip(f"{option.NAME}: {option.DESCRIPTION}")
            # XXX: causes an itemChanged event for the tree
            self._combo_box.currentTextChanged.connect(lambda x: self.setText(0, self._combo_box.currentText()))
            self.treeWidget().setItemWidget(self, 0, self._combo_box)

        # should make a boolean click option
        else:
            self.setFlags(self.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            if enabled:
                self.setCheckState(0, Qt.CheckState.Checked)
            else:
                self.setCheckState(0, Qt.CheckState.Unchecked)

    @property
    def state(self):
        if self._combo_box:
            return self._combo_box.currentText()
        else:
            return bool(self.checkState(0) == Qt.CheckState.Checked)


class QDecompilationOptions(QWidget):
    """
    The widget for selecting values for decompilation options. Will synchronize its status back to its parent (passed
    in parameter) code view with the Apply button is pressed.

    Since some options have default values depending on the current arch and os, it is important to call
    reload(force=True) to reset values to their defaults whenever the current project changes.
    """

    def __init__(self, code_view, instance: Instance) -> None:
        super().__init__()

        self.dirty = True

        self._code_view: CodeView = code_view
        self._instance = instance
        self._options = None
        self._opti_passes = None
        self._peephole_opts = None

        # widgets
        self._search_box: QLineEdit
        self._treewidget: QTreeWidget
        self._apply_btn: QPushButton

        self._qoptions = []
        self._qoptipasses = []
        self._qpeephole_opts = []

        self._init_widgets()

        self.reload(True)

    def reload(self, force: bool = False) -> None:
        if force or self._options is None:
            self._options = self.get_default_options()

        if force or self._opti_passes is None:
            if not self._instance.project.am_none:
                self._opti_passes = self.get_all_passes()
            else:
                self._opti_passes = []

        if force or self._peephole_opts is None:
            self._peephole_opts = self.get_all_peephole_opts()

        self._reload_options(force)
        self._set_visibility(self._search_box.text())

    def _on_item_changed(self, item, _column) -> None:
        if getattr(item.option, "clears_cache", True):
            self.dirty = True

    def _on_apply_pressed(self) -> None:
        if self.dirty:
            self.dirty = False
            # clear the cached version
            self._code_view.decompile(reset_cache=True)
        else:
            if not self._code_view.codegen.am_none:
                self._code_view.codegen.reapply_options(self.option_and_values)
                self._code_view.codegen.am_event()

    @property
    def selected_passes(self):
        selected = []
        for item in self._qoptipasses:
            if item.state:
                selected.append(item.option)
        return selected

    @property
    def selected_peephole_opts(self):
        selected = []
        for item in self._qpeephole_opts:
            if item.state:
                selected.append(item.option)
        return selected

    @property
    def option_and_values(self):
        return [(item.option, item.state) for item in self._qoptions]

    def get_default_options(self):  # pylint: disable=no-self-use
        return dec_options

    def get_default_passes(self):
        if self._instance is None or self._instance.project.am_none:
            return []
        return get_default_optimization_passes(self._instance.project.arch, self._instance.project.simos.name) + [
            x for x, de in self._code_view.workspace.plugins.optimization_passes() if de
        ]

    def get_all_passes(self):
        if self._instance is None or self._instance.project.am_none:
            return []
        return get_optimization_passes(self._instance.project.arch, self._instance.project.simos.name) + [
            x for x, _ in self._code_view.workspace.plugins.optimization_passes()
        ]

    def get_default_peephole_opts(self):  # pylint: disable=no-self-use
        return MULTI_STMT_OPTS + STMT_OPTS + EXPR_OPTS

    def get_all_peephole_opts(self):  # pylint: disable=no-self-use
        return MULTI_STMT_OPTS + STMT_OPTS + EXPR_OPTS

    def _init_widgets(self) -> None:
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

    def _reload_options(self, reset_values: bool = False) -> None:
        vals_options = dict(self.option_and_values)
        vals_peephole = self.selected_peephole_opts
        vals_passes = self.selected_passes

        self._treewidget.clear()
        self._qoptions.clear()
        self._qoptipasses.clear()
        self._qpeephole_opts.clear()

        categories = {}

        # populate the tree widget with new options
        for option in sorted(self._options, key=lambda x: x.NAME):
            if option.category in categories:
                category = categories[option.category]
            else:
                category = QTreeWidgetItem(self._treewidget, [option.category])
                categories[option.category] = category

            enabled = option.default_value if reset_values else vals_options.get(option, option.default_value)
            w = QDecompilationOption(category, option, OptionType.OPTION, enabled=enabled)
            self._qoptions.append(w)

        passes_category = QTreeWidgetItem(self._treewidget, ["Optimization Passes"])
        categories["passes"] = passes_category

        default_passes = set(self.get_default_passes())
        for pass_ in self._opti_passes:
            enabled = pass_ in default_passes if reset_values else pass_ in vals_passes
            w = QDecompilationOption(passes_category, pass_, OptionType.OPTIMIZATION_PASS, enabled=enabled)
            self._qoptipasses.append(w)

        po_category = QTreeWidgetItem(self._treewidget, ["Peephole Optimizations"])
        categories["peephole_opts"] = po_category

        default_peephole_opts = self.get_default_peephole_opts()
        for opt_ in self._peephole_opts:
            enabled = opt_ in default_peephole_opts if reset_values else opt_ in vals_peephole
            w = QDecompilationOption(po_category, opt_, OptionType.PEEPHOLE_OPTIMIZATION, enabled=enabled)
            self._qpeephole_opts.append(w)

        # expand all
        self._treewidget.expandAll()

    def _set_visibility(self, filter_by: str | None = None) -> None:
        for w in self._qoptions:
            w.setHidden(
                bool(filter_by) and not (filter_by in w.option.NAME.lower() or filter_by in w.option.category.lower())
            )
        for w in self._qoptipasses:
            w.setHidden(
                bool(filter_by) and not (filter_by in w.option.__name__.lower() or filter_by in w.option.NAME.lower())
            )
        for w in self._qpeephole_opts:
            w.setHidden(
                bool(filter_by)
                and not (filter_by in w.option.NAME.lower() or filter_by in w.option.DESCRIPTION.lower())
            )

    def _on_search_box_text_changed(self, text: str) -> None:
        self._set_visibility(filter_by=text)
