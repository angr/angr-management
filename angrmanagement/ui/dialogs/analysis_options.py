import os
from typing import TYPE_CHECKING, Optional, Sequence

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QSpinBox,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.config import IMG_LOCATION
from angrmanagement.data.analysis_options import (
    AnalysesConfiguration,
    AnalysisOption,
    BoolAnalysisOption,
    ChoiceAnalysisOption,
    IntAnalysisOption,
    StringAnalysisOption,
)

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class AnalysisOptionWidgetMapper:
    """
    Analysis option widget creation and event handling.
    """

    def __init__(self, option: AnalysisOption):
        self.option: AnalysisOption = option
        self.widget: Optional[QWidget] = None

    def create_widget(self) -> QWidget:
        raise NotImplementedError

    @classmethod
    def get_mapper_for_option(cls, option: AnalysisOption) -> "AnalysisOptionWidgetMapper":
        if isinstance(option, BoolAnalysisOption):
            return BoolAnalysisOptionWidgetMapper(option)
        elif isinstance(option, IntAnalysisOption):
            return IntAnalysisOptionWidgetMapper(option)
        elif isinstance(option, ChoiceAnalysisOption):
            return ChoiceAnalysisOptionWidgetMapper(option)
        elif isinstance(option, StringAnalysisOption):
            return StringAnalysisOptionWidgetMapper(option)
        else:
            raise ValueError("Mapper not implemented")


class BoolAnalysisOptionWidgetMapper(AnalysisOptionWidgetMapper):
    """
    Analysis option widget creation and event handling for boolean options.
    """

    option: BoolAnalysisOption

    def create_widget(self, parent=None) -> QCheckBox:
        self.widget = QCheckBox(parent)
        self.widget.setText(self.option.display_name)
        if self.option.tooltip:
            self.widget.setToolTip(self.option.tooltip)
        self.widget.setChecked(self.option.value)
        self.widget.stateChanged.connect(self._on_checkbox_changed)
        return self.widget

    def _on_checkbox_changed(self, _):
        self.option.value = self.widget.isChecked()


class StringAnalysisOptionWidgetMapper(AnalysisOptionWidgetMapper):
    """
    Analysis option widget for string answers
    """

    option: StringAnalysisOption

    def __init__(self, option: AnalysisOption):
        super().__init__(option)

        self.checkbox = None
        self.textbox = None

    def create_widget(self, parent=None) -> QWidget:
        self.textbox = QLineEdit(self.option.value)
        self.textbox.textChanged.connect(self._on_text_changed)

        layout = QHBoxLayout()

        if self.option.optional:
            checkbox = QCheckBox()
            checkbox.setText(self.option.display_name)
            if self.option.tooltip:
                checkbox.setToolTip(self.option.tooltip)
            checkbox.clicked.connect(self._on_toggled)
            self.checkbox = checkbox
            layout.addWidget(checkbox)
            self._on_toggled()  # enable or disable the textbox
        else:
            lbl = QLabel()
            lbl.setText(self.option.display_name)
            if self.option.tooltip:
                lbl.setToolTip(self.option.tooltip)
            layout.addWidget(lbl)

        layout.addWidget(self.textbox)
        self.widget = QWidget(parent)
        self.widget.setLayout(layout)
        return self.widget

    def _on_toggled(self):
        self.textbox.setEnabled(self.checkbox.isChecked())
        self.option.enabled = self.checkbox.isChecked()

    def _on_text_changed(self, value: str):
        self.option.value = value


class IntAnalysisOptionWidgetMapper(AnalysisOptionWidgetMapper):
    """
    Analysis option widget creation and event handling for integer options.
    """

    option: IntAnalysisOption

    def create_widget(self, parent=None) -> QWidget:
        spinbox = QSpinBox()
        spinbox.setValue(self.option.value)
        if self.option.tooltip:
            spinbox.setToolTip(self.option.tooltip)
        spinbox.valueChanged.connect(self._on_dial_changed)
        if self.option.minimum_value is not None:
            spinbox.setMinimum(self.option.minimum_value)
        if self.option.maximum_value is not None:
            spinbox.setMaximum(self.option.maximum_value)

        lbl = QLabel()
        lbl.setText(self.option.display_name)
        if self.option.tooltip:
            lbl.setToolTip(self.option.tooltip)

        layout = QHBoxLayout()
        layout.addWidget(lbl)
        layout.addWidget(spinbox)

        self.widget = QWidget(parent)
        self.widget.setLayout(layout)
        return self.widget

    def _on_dial_changed(self, value: int):
        self.option.value = value


class ChoiceAnalysisOptionWidgetMapper(AnalysisOptionWidgetMapper):
    """
    Analysis option widget creation and event handling for choice options.
    """

    option: ChoiceAnalysisOption

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.combobox = None

    def create_widget(self, parent=None) -> QWidget:
        self.combobox = QComboBox()
        for data, txt in self.option.choices.items():
            self.combobox.addItem(txt, data)
        self.combobox.setCurrentIndex(self.combobox.findData(self.option.value))
        self.combobox.currentIndexChanged.connect(self._on_combo_changed)

        lbl = QLabel()
        lbl.setText(self.option.display_name)
        if self.option.tooltip:
            lbl.setToolTip(self.option.tooltip)

        layout = QHBoxLayout()
        layout.addWidget(lbl)
        layout.addStretch()
        layout.addWidget(self.combobox)

        self.widget = QWidget(parent)
        self.widget.setLayout(layout)
        return self.widget

    def _on_combo_changed(self, index):
        self.option.value = self.combobox.itemData(index)


class AnalysisOptionsDialog(QDialog):
    """
    Dialog displaying available analyses and configuration options.
    """

    def __init__(self, analyses: AnalysesConfiguration, workspace: "Workspace", parent=None):
        super().__init__(parent)
        self._workspace: Workspace = workspace
        self._analyses: AnalysesConfiguration = analyses
        self._mappers: Sequence[AnalysisOptionWidgetMapper] = []
        self.setWindowTitle("Run Analysis")
        self._init_widgets()

    def sizeHint(self, *args, **kwargs):  # pylint: disable=unused-argument,no-self-use
        return QSize(800, 600)

    #
    # Private methods
    #

    def _init_widgets(self):
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

        for analysis in self._analyses.analyses:
            item = QListWidgetItem(analysis.display_name, self._analysis_list)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if analysis.enabled else Qt.Unchecked)
            self._analysis_list.addItem(item)

        #
        # Analysis details
        #
        self._analysis_description_label = QLabel()
        self._analysis_description_label.setWordWrap(True)
        layout = QVBoxLayout()
        layout.addWidget(self._analysis_description_label)
        description_gbox = QGroupBox("Description")
        description_gbox.setLayout(layout)

        self._options_layout = QVBoxLayout()
        options_gbox = QGroupBox("Options")
        options_gbox.setLayout(self._options_layout)

        details_layout = QVBoxLayout()
        details_layout.addWidget(description_gbox)
        details_layout.addWidget(options_gbox)

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

    def _update_item_details(self):
        while self._options_layout.count():
            item = self._options_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        self._mappers = []

        selected = self._analysis_list.selectedItems()
        if selected:
            analysis = self._analyses[self._analysis_list.indexFromItem(selected[0]).row()]
            self._analysis_description_label.setText(analysis.description)

            for option in analysis.options.values():
                mapper = AnalysisOptionWidgetMapper.get_mapper_for_option(option)
                widget = mapper.create_widget(self)
                self._options_layout.addWidget(widget)
                self._mappers.append(mapper)
        else:
            self._analysis_description_label.setText("Select analysis to view options.")

        self._options_layout.addStretch()

    #
    # Event handlers
    #

    def _on_item_changed(self, item):
        analysis = self._analyses[self._analysis_list.indexFromItem(item).row()]
        analysis.enabled = item.checkState() == Qt.Checked
        self._update_item_details()

    def _on_run_clicked(self):
        self.accept()
