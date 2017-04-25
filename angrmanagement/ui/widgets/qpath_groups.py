
from PySide.QtGui import QFrame, QLabel, QComboBox, QHBoxLayout, QVBoxLayout, QLineEdit, QPushButton, QGroupBox, \
    QCheckBox, QTabWidget, QListWidget, QListWidgetItem
from PySide.QtCore import QSize, Qt

from ..widgets.qpathgroup_viewer import QPathGroupViewer


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
        self._avoids_list = None  # type: QListWidget
        self._pathgroup_viewer = None  # type: QPathGroupViewer
        self._oneactive_checkbox = None  # type: QCheckBox

        self._init_widgets()

        self._pathgroups_list.currentIndexChanged.connect(self._on_pathgroup_selection_internal)

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

    #
    # Public methods
    #

    def refresh(self):
        for i, pg_desc in enumerate(self._path_groups.groups):
            self._pathgroups_list.setItemText(i, pg_desc.name)

        current_index = self._pathgroups_list.currentIndex()
        if current_index != -1:
            # refresh the pathtrees
            self._pathgroups_list.currentIndexChanged.emit(current_index)

    def reload(self):
        for pg in self._path_groups.groups:
            self.add_pathgroup(pg)

    def add_pathgroup(self, pg_desc):
        self._pathgroups_list.addItem(pg_desc.name, pg_desc)

    def select_pathgroup_desc(self, pg_desc):
        idx = self._pathgroups_list.findText(pg_desc.name)

        if idx != -1:
            self._pathgroups_list.setCurrentIndex(idx)

    def get_pathgroup(self, index):
        return self._pathgroups_list.itemData(index).pg

    def current_pathgroup(self):
        idx = self._pathgroups_list.currentIndex()
        if idx != -1:
            return self.get_pathgroup(idx)

        return None

    def add_avoid_address(self, addr):

        for i in xrange(self._avoids_list.count()):
            item = self._avoids_list.item(i)  # type: QListWidgetItem
            if int(item.text(), 16) == addr:
                # deduplicate
                return

        item = QListWidgetItem("%#x" % addr)
        item.setData(Qt.CheckStateRole, Qt.Checked)

        self._avoids_list.addItem(item)

    #
    # Overridden methods
    #

    #
    # Initialization
    #

    def _init_widgets(self):

        tab = QTabWidget()

        self._init_pathgroups_tab(tab)
        self._init_settings_tab(tab)
        self._init_avoids_tab(tab)

        layout = QVBoxLayout()
        layout.addWidget(tab)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    def _init_pathgroups_tab(self, tab):

        # pathgroups list

        pathgroups_label = QLabel(self)
        pathgroups_label.setText('PathGroup')

        pathgroups_list = QComboBox(self)
        self._pathgroups_list = pathgroups_list

        pg_layout = QHBoxLayout()
        pg_layout.addWidget(pathgroups_label)
        pg_layout.addWidget(pathgroups_list)

        # path group information
        viewer = QPathGroupViewer(None)
        self._pathgroup_viewer = viewer

        #
        # Buttons
        #

        # step button
        step_button = QPushButton()
        step_button.setText('Step Path Group')
        step_button.released.connect(self._on_step_clicked)

        # step until branch
        step_until_branch_button = QPushButton('Step Path Group until branch')
        step_until_branch_button.released.connect(self._on_step_until_branch_clicked)

        # explore button
        explore_button = QPushButton('Explore')
        explore_button.released.connect(self._on_explore_clicked)

        # buttons layout
        buttons_layout = QVBoxLayout()
        layout = QHBoxLayout()
        layout.addWidget(explore_button)
        buttons_layout.addLayout(layout)

        layout = QHBoxLayout()
        layout.addWidget(step_button)
        layout.addWidget(step_until_branch_button)
        buttons_layout.addLayout(layout)

        pathgroups_layout = QVBoxLayout()
        pathgroups_layout.addLayout(pg_layout)
        pathgroups_layout.addWidget(viewer)
        pathgroups_layout.addLayout(buttons_layout)

        frame = QFrame()
        frame.setLayout(pathgroups_layout)

        tab.addTab(frame, 'General')

    def _init_settings_tab(self, tab):

        oneactive_checkbox = QCheckBox("Keep at most one active path")
        oneactive_checkbox.setChecked(False)
        self._oneactive_checkbox = oneactive_checkbox

        settings_layout = QVBoxLayout()
        settings_layout.addWidget(oneactive_checkbox)
        settings_layout.addStretch(0)

        frame = QFrame()
        frame.setLayout(settings_layout)

        tab.addTab(frame, 'Settings')

    def _init_avoids_tab(self, tab):

        avoids_list = QListWidget()
        self._avoids_list = avoids_list

        layout = QVBoxLayout()
        layout.addWidget(avoids_list)

        frame = QFrame()
        frame.setLayout(layout)

        tab.addTab(frame, 'Avoids')


    #
    # Event handlers
    #

    def _on_step_clicked(self):
        pg = self.current_pathgroup()
        if pg is not None:
            self.path_groups.step_pathgroup(pg, until_branch=False, async=False)

            if self._oneactive_checkbox.isChecked():
                pg = self.current_pathgroup()  # pg is updated
                if self._filter_actives(pg):
                    self.path_groups.refresh_widget()

    def _on_step_until_branch_clicked(self):
        pg = self.current_pathgroup()
        if pg is not None:
            self.path_groups.step_pathgroup(pg, until_branch=True)

            if self._oneactive_checkbox.isChecked():
                pg = self.current_pathgroup()  # pg is updated
                if self._filter_actives(pg):
                    self.path_groups.refresh_widget()

    def _on_explore_clicked(self):
        pg = self.current_pathgroup()

        if pg is not None:

            def _step_callback(pg):
                # refresh the widget
                # self.path_groups.refresh_widget()

                if self._oneactive_checkbox.isChecked():
                    self._filter_actives(pg)

                # print "Currently exploring ", pg, pg.active

                return pg

            avoids = [ ]
            for i in xrange(self._avoids_list.count()):
                item = self._avoids_list.item(i)  # type: QListWidgetItem
                if item.checkState() == Qt.Checked:
                    avoids.append(int(item.text(), 16))

            self.path_groups.explore_pathgroup(pg, avoid=avoids, find=[], step_callback=_step_callback)

    #
    # Private methods
    #

    def _on_pathgroup_selection_internal(self, idx):

        self._pathgroup_viewer.pathgroup = self.current_pathgroup()

        if self.on_pathgroup_selection is not None:
            self.on_pathgroup_selection(idx)

    @staticmethod
    def _filter_actives(pg):
        if len(pg.active) > 1:
            pg.stashes['stashed'].extend(pg.active[1:])
            pg.stashes['active'] = pg.active[:1]

            return True

        return False
