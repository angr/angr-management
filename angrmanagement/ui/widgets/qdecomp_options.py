from __future__ import annotations

from typing import TYPE_CHECKING

from angr.analyses.decompiler import DECOMPILATION_PRESETS
from angr.analyses.decompiler.decompilation_options import options as dec_options
from angr.analyses.decompiler.optimization_passes import get_optimization_passes
from angr.analyses.decompiler.peephole_optimizations import EXPR_OPTS, MULTI_STMT_OPTS, STMT_OPTS
from PySide6.QtCore import QSize
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTreeWidget,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.ui.widgets.qproperty_editor import (
    BoolPropertyItem,
    ComboPropertyItem,
    GroupPropertyItem,
    PropertyModel,
    QPropertyEditor,
)

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.views.code_view import CodeView


def map_option_to_property(option, enabled):
    if hasattr(option, "value_type") and not isinstance(option.value_type, bool) and option.candidate_values:
        return ComboPropertyItem(
            option.NAME, option.default_value, option.candidate_values, description=option.DESCRIPTION, option=option
        )
    else:
        return BoolPropertyItem(option.NAME, enabled, description=option.DESCRIPTION, option=option)


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
        self._preset_cmb: QComboBox
        self._tree_view: QTreeWidget
        self._apply_btn: QPushButton

        self._qoptions = []
        self._qoptipasses = []
        self._qpeephole_opts = []

        self._init_widgets()

        self.reload(True)

    def sizeHint(self):  # pylint:disable=no-self-use
        return QSize(400, 400)

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

    def _on_item_changed(self, item, _) -> None:
        if getattr(item.extra["option"], "clears_cache", True):
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
            if item.value:
                selected.append(item.extra["option"])
        return selected

    @property
    def selected_peephole_opts(self):
        selected = []
        for item in self._qpeephole_opts:
            if item.value:
                selected.append(item.extra["option"])
        return selected

    @property
    def option_and_values(self):
        return [(item.extra["option"], item.value) for item in self._qoptions]

    def get_default_options(self):  # pylint: disable=no-self-use
        return dec_options

    def get_default_passes(self):
        if self._instance is None or self._instance.project.am_none:
            return []
        default_preset = DECOMPILATION_PRESETS[self._preset_cmb.currentText()]
        return default_preset.get_optimization_passes(
            self._instance.project.arch, self._instance.project.simos.name
        ) + [x for x, de in self._code_view.workspace.plugins.optimization_passes() if de]

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
        preset_lyt = QHBoxLayout()
        preset_lyt.setContentsMargins(0, 0, 0, 0)
        preset_lyt.setSpacing(3)

        preset_lyt.addWidget(QLabel("Preset:"))
        self._preset_cmb = QComboBox()
        presets = sorted([n for n in DECOMPILATION_PRESETS if n != "default"])
        self._preset_cmb.addItems(presets)
        self._preset_cmb.setCurrentIndex(
            next(i for i, n in enumerate(presets) if DECOMPILATION_PRESETS[n] is DECOMPILATION_PRESETS["default"])
        )
        self._preset_cmb.activated.connect(lambda: self.reload(force=True))
        preset_lyt.addWidget(self._preset_cmb, 1)

        self._tree_view = QPropertyEditor()

        # refresh button
        self._apply_btn = QPushButton("Apply")
        self._apply_btn.clicked.connect(self._on_apply_pressed)

        layout = QVBoxLayout()
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(3)
        layout.addLayout(preset_lyt)
        layout.addWidget(self._tree_view)
        layout.addWidget(self._apply_btn)

        self.setLayout(layout)

    def _reload_options(self, reset_values: bool = False) -> None:
        vals_options = dict(self.option_and_values)
        vals_peephole = self.selected_peephole_opts
        vals_passes = self.selected_passes

        self._qoptions.clear()
        self._qoptipasses.clear()
        self._qpeephole_opts.clear()

        categories = {}
        root = GroupPropertyItem("Root")
        model = PropertyModel(root)
        model.valueChanged.connect(self._on_item_changed)

        # populate the tree widget with new options
        for option in sorted(self._options, key=lambda x: x.NAME):
            if option.category in categories:
                category = categories[option.category]
            else:
                category = GroupPropertyItem(option.category, description=option.category)
                categories[option.category] = category
                root.addChild(category)

            enabled = option.default_value if reset_values else vals_options.get(option, option.default_value)
            w = map_option_to_property(option, enabled)
            category.addChild(w)
            self._qoptions.append(w)

        passes_category = GroupPropertyItem("Optimization Passes", description="Optimization Passes")
        categories["passes"] = passes_category
        root.addChild(passes_category)

        default_passes = set(self.get_default_passes())
        for pass_ in self._opti_passes:
            enabled = pass_ in default_passes if reset_values else pass_ in vals_passes
            w = map_option_to_property(pass_, enabled)
            passes_category.addChild(w)
            self._qoptipasses.append(w)

        po_category = GroupPropertyItem("Peephole Optimizations", description="Peephole Optimizations")
        categories["peephole_opts"] = po_category
        root.addChild(po_category)

        default_peephole_opts = self.get_default_peephole_opts()
        for opt_ in self._peephole_opts:
            enabled = opt_ in default_peephole_opts if reset_values else opt_ in vals_peephole
            w = map_option_to_property(opt_, enabled)
            po_category.addChild(w)
            self._qpeephole_opts.append(w)

        self._tree_view.setModel(model)
        self.dirty = True
