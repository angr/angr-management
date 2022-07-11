import os
from typing import Optional, Sequence
import logging

from PySide2.QtGui import QIcon
from PySide2.QtWidgets import QDialog, QVBoxLayout, QFrame, QGroupBox, \
    QListWidgetItem, QListWidget, QDialogButtonBox, QLabel, QCheckBox, QSplitter, QWidget
from PySide2.QtCore import Qt, QSize

from ...config import IMG_LOCATION
from ...data.analysis_options import AnalysisOption, AnalysesConfiguration, BoolAnalysisOption

l = logging.getLogger(__name__)


class AnalysisOptionWidgetMapper:
    """
    Analysis option widget creation and event handling.
    """

    def __init__(self, option: AnalysisOption):
        self.option: AnalysisOption = option
        self.widget: Optional[QWidget] = None

    def create_widget(self) -> QWidget:
        raise NotImplementedError()

    @classmethod
    def get_mapper_for_option(cls, option: AnalysisOption) -> 'AnalysisOptionWidgetMapper':
        if isinstance(option, BoolAnalysisOption):
            return BoolAnalysisOptionWidgetMapper(option)
        else:
            raise ValueError('Mapper not implemented')


class BoolAnalysisOptionWidgetMapper(AnalysisOptionWidgetMapper):
    """
    Analysis option widget creation and event handling for boolean options.
    """

    def create_widget(self, parent=None) -> QCheckBox:
        self.widget = QCheckBox(parent)
        self.widget.setText(self.option.display_name)
        self.widget.setChecked(self.option.value)
        self.widget.stateChanged.connect(self._on_checkbox_changed)
        return self.widget

    def _on_checkbox_changed(self, state):
        self.option.value = (state == Qt.Checked)


class AnalysisOptionsDialog(QDialog):
    """
    Dialog displaying available analyses and configuration options.
    """

    def __init__(self, analyses: AnalysesConfiguration, workspace: 'Workspace', parent=None):
        super().__init__(parent)
        self._workspace: 'Workspace' = workspace
        self._analyses: AnalysesConfiguration = analyses
        self._mappers: Sequence[AnalysisOptionWidgetMapper] = []
        self.setWindowTitle('Run Analysis')
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
        analyses_gbox = QGroupBox('Available Analyses')
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
        description_gbox = QGroupBox('Description')
        description_gbox.setLayout(layout)

        self._options_layout = QVBoxLayout()
        options_gbox = QGroupBox('Options')
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
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText('&Run Analysis')
        buttons.button(QDialogButtonBox.StandardButton.Ok).setIcon(QIcon(os.path.join(IMG_LOCATION, 'run-icon.png')))
        buttons.accepted.connect(self._on_run_clicked)
        buttons.rejected.connect(self.reject)
        self.main_layout.addWidget(buttons)

        self._analysis_list.itemSelectionChanged.connect(self._update_item_details)
        self._analysis_list.itemChanged.connect(self._on_item_changed)

        if len(self._analyses) > 0:
            self._analysis_list.setCurrentRow(0)

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
            self._analysis_description_label.setText('Select analysis to view options.')

        self._options_layout.addStretch()

    #
    # Event handlers
    #

    def _on_item_changed(self, item):
        analysis = self._analyses[self._analysis_list.indexFromItem(item).row()]
        analysis.enabled = (item.checkState() == Qt.Checked)
        self._update_item_details()

    def _on_run_clicked(self):
        self.accept()
