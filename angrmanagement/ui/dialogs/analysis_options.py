from __future__ import annotations

import os
from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGroupBox,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QSplitter,
    QVBoxLayout,
)

from angrmanagement.consts import IMG_LOCATION
from angrmanagement.logic import GlobalInfo
from angrmanagement.present.analysis_options import (
    LANGUAGE_DEPENDENT_ANALYSES,
    RUST_DEPENDENT_ANALYSES,
    is_language_option,
    option_row,
    set_language,
)
from angrmanagement.ui.widgets.qproperty_editor import (
    BoolPropertyItem,
    ComboPropertyItem,
    GroupPropertyItem,
    IntPropertyItem,
    PropertyModel,
    QPropertyEditor,
    TextPropertyItem,
)

if TYPE_CHECKING:
    from angrmanagement.data.analysis_options import (
        AnalysesConfiguration,
        AnalysisOption,
    )
    from angrmanagement.ui.workspace import Workspace


def map_option_to_property(option: AnalysisOption):
    """The property editor item of ``option``, from the row the terminal's option sheet shows too."""
    row = option_row(option)
    if row.kind == "bool":
        return BoolPropertyItem(row.label, row.value, description=row.description, option=option)
    if row.kind == "int":
        return IntPropertyItem(
            row.label, row.value, minimum=row.minimum, maximum=row.maximum, description=row.description, option=option
        )
    if row.kind == "choice":
        return ComboPropertyItem(row.label, row.value, dict(row.choices), description=row.description, option=option)
    return TextPropertyItem(row.label, row.value, description=row.description, option=option)


class AnalysisOptionsDialog(QDialog):
    """
    Dialog displaying available analyses and configuration options.
    """

    def __init__(self, analyses: AnalysesConfiguration, workspace: Workspace, parent=None) -> None:
        super().__init__(parent)
        self._workspace: Workspace = workspace
        self._analyses: AnalysesConfiguration = analyses
        self._init_widgets()
        self.setWindowTitle("Run Analysis")
        self.setMinimumSize(self.sizeHint())
        self.adjustSize()

    def sizeHint(self):  # pylint: disable=no-self-use
        return QSize(800, 600)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)

        #
        # Available analyses
        #
        self._analysis_list = QListWidget()
        layout = QVBoxLayout()
        layout.addWidget(self._analysis_list)
        analyses_gbox = QGroupBox("Available Analyses")
        analyses_gbox.setLayout(layout)

        self._items_by_name: dict[str, QListWidgetItem] = {}
        for analysis in self._analyses.analyses:
            item = QListWidgetItem(analysis.display_name, self._analysis_list)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if analysis.enabled else Qt.CheckState.Unchecked)
            self._analysis_list.addItem(item)
            self._items_by_name[analysis.name] = item

        #
        # Analysis details
        #
        self._analysis_description_label = QLabel()
        self._analysis_description_label.setWordWrap(True)
        layout = QVBoxLayout()
        layout.addWidget(self._analysis_description_label)
        description_gbox = QGroupBox("Analysis Description")
        description_gbox.setLayout(layout)

        self._options_tree = QPropertyEditor()

        details_layout = QVBoxLayout()
        details_layout.addWidget(description_gbox)
        details_layout.addWidget(self._options_tree)

        splitter = QSplitter()
        left_frame = QFrame()
        left_layout = QVBoxLayout()
        left_layout.addWidget(analyses_gbox)
        left_frame.setLayout(left_layout)
        splitter.addWidget(left_frame)
        right_frame = QFrame()
        right_frame.setLayout(details_layout)
        splitter.addWidget(right_frame)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        left_margins = left_layout.contentsMargins()
        left_layout.setContentsMargins(0, 0, left_margins.right(), 0)
        details_margins = details_layout.contentsMargins()
        details_layout.setContentsMargins(details_margins.left(), 0, 0, 0)
        self.main_layout.addWidget(splitter)

        #
        # Dialog buttons
        #
        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        ok_button.setText("&Run Analysis")
        ok_button.setIcon(QIcon(os.path.join(IMG_LOCATION, "run-icon.svg")))
        buttons.accepted.connect(self._on_run_clicked)
        buttons.rejected.connect(self.reject)
        self.main_layout.addWidget(buttons)

        self._analysis_list.itemSelectionChanged.connect(self._update_item_details)
        self._analysis_list.itemChanged.connect(self._on_item_changed)

        if len(self._analyses) > 0:
            self._analysis_list.setCurrentRow(0)

        ok_button.setFocus()

    def _update_item_details(self) -> None:
        selected = self._analysis_list.selectedItems()
        if selected:
            analysis = self._analyses[self._analysis_list.indexFromItem(selected[0]).row()]
            self._analysis_description_label.setText(analysis.description)
            self._init_analysis_options_model(analysis)
        else:
            self._analysis_description_label.setText("Select analysis to view options.")

    def _init_analysis_options_model(self, analysis):
        root = GroupPropertyItem("Root")
        for option in analysis.options.values():
            root.addChild(map_option_to_property(option))
        model = PropertyModel(root)

        def on_value_changed(prop, value):
            prop.extra["option"].value = value
            if is_language_option(analysis, prop.extra["option"]):
                self._on_language_changed(value)

        model.valueChanged.connect(on_value_changed)
        self._options_tree.setModel(model)

    def _on_language_changed(self, language) -> None:
        for prompt in set_language(self._analyses, language):
            reply = GlobalInfo.ui_services.question(prompt.title, prompt.text, ["Yes", "No"], "Yes")
            if reply != "Yes":
                continue
            prompt.apply()
            for config in prompt.targets:
                item = self._items_by_name.get(config.name)
                if item is not None:
                    item.setCheckState(Qt.CheckState.Checked if prompt.want_enabled else Qt.CheckState.Unchecked)

    #
    # Event handlers
    #

    def _on_item_changed(self, item) -> None:
        analysis = self._analyses[self._analysis_list.indexFromItem(item).row()]
        analysis.enabled = item.checkState() == Qt.CheckState.Checked
        self._update_item_details()

    def _on_run_clicked(self) -> None:
        self.accept()


# the language tables moved to angrmanagement.present.analysis_options; they stay importable from here
__all__ = ["LANGUAGE_DEPENDENT_ANALYSES", "RUST_DEPENDENT_ANALYSES", "AnalysisOptionsDialog", "map_option_to_property"]
