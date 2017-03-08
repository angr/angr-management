
from PySide.QtGui import QFrame, QLabel, QComboBox, QHBoxLayout, QVBoxLayout, QLineEdit, QPushButton
from PySide.QtCore import QSize


class QPathGroups(QFrame):
    def __init__(self, path_groups, parent=None):
        """
        :param PathGroups path_groups:  A manager that manages a collection of PathGroup instances.
        :param object parent:           The parent widget.
        """
        super(QPathGroups, self).__init__(parent)

        self._path_groups = None
        self._on_pathgroup_selection = None

        self.path_groups = path_groups

        self._pathgroups_list = None  # type: QComboBox

        self._init_widgets()

    #
    # Properties
    #

    @property
    def path_groups(self):
        return self._path_groups

    @path_groups.setter
    def path_groups(self, v):
        if v is not self._path_groups:
            self._path_groups = v

            if self._path_groups is not None:
                self._path_groups.link_widget(self)

    @property
    def on_pathgroup_selection(self):
        return self._on_pathgroup_selection

    @on_pathgroup_selection.setter
    def on_pathgroup_selection(self, v):
        if v is not self._on_pathgroup_selection:
            self._on_pathgroup_selection = v
            self._pathgroups_list.currentIndexChanged.connect(self._on_pathgroup_selection)

    #
    # Public methods
    #

    def refresh(self):
        for i, pg in enumerate(self._path_groups.groups):
            self._pathgroups_list.setItemText(i, repr(pg))

        current_index = self._pathgroups_list.currentIndex()
        if current_index != -1:
            # refresh the pathtrees
            self._pathgroups_list.currentIndexChanged.emit(current_index)

    def reload(self):
        for pg in self._path_groups.groups:
            self.add_pathgroup(pg)

    def add_pathgroup(self, pg):
        self._pathgroups_list.addItem(repr(pg), pg)

    def select_pathgroup(self, pg):
        idx = self._pathgroups_list.findData(pg)

        if idx != -1:
            self._pathgroups_list.setCurrentIndex(idx)

    def get_pathgroup(self, index):
        return self._pathgroups_list.itemData(index)

    def current_pathgroup(self):
        idx = self._pathgroups_list.currentIndex()
        if idx != -1:
            return self.get_pathgroup(idx)

        return None

    #
    # Overridden methods
    #

    #
    # Initialization
    #

    def _init_widgets(self):

        # pathgroups list

        pathgroups_label = QLabel(self)
        pathgroups_label.setText('PathGroup')

        pathgroups_list = QComboBox(self)
        self._pathgroups_list = pathgroups_list

        # step button
        step_button = QPushButton()
        step_button.setText('Step')
        step_button.released.connect(self._on_step_clicked)

        pathgroups_layout = QHBoxLayout()
        pathgroups_layout.addWidget(pathgroups_label)
        pathgroups_layout.addWidget(pathgroups_list)
        pathgroups_layout.addWidget(step_button)

        layout = QVBoxLayout()
        layout.addLayout(pathgroups_layout)

        layout.addStretch()

        self.setLayout(layout)

    #
    # Event handlers
    #

    def _on_step_clicked(self):
        pg = self.current_pathgroup()
        if pg is not None:
            self.path_groups.step_pathgroup(pg)
