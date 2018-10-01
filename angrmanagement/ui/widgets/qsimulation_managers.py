from PySide2.QtWidgets import QFrame, QLabel, QComboBox, QHBoxLayout, QVBoxLayout, QLineEdit, QPushButton, QGroupBox, \
    QCheckBox, QTabWidget, QListWidget, QListWidgetItem
from PySide2.QtCore import QSize, Qt

from ...data.jobs import SimgrStepJob, SimgrExploreJob
from ...data.instance import Instance
from ..widgets.qsimulation_manager_viewer import QSimulationManagerViewer


class QSimulationManagers(QFrame):
    def __init__(self, instance, simgr, state, parent=None):
        """
        :param Instance instance:       The data source for this project
        :param object parent:           The parent widget.
        """
        super(QSimulationManagers, self).__init__(parent)

        self.instance = instance
        self.simgrs = instance.simgrs
        self.simgr = simgr
        self.state = state

        self._simgrs_list = None  # type: QComboBox
        self._avoids_list = None  # type: QListWidget
        self._simgr_viewer = None  # type: QSimulationManagerViewer
        self._oneactive_checkbox = None  # type: QCheckBox

        self._init_widgets()

        self.simgr.am_subscribe(self._watch_simgr)
        self.simgrs.am_subscribe(self._watch_simgrs)
        self.state.am_subscribe(self._watch_state)

    #
    # Public methods
    #

    def refresh(self):
        self._simgrs_list.clear()
        for i, simgr in enumerate(self.simgrs):
            self._simgrs_list.addItem(simgr.am_name)
            if simgr is self.simgr.am_obj:
                self._simgrs_list.setCurrentIndex(i)

    def add_avoid_address(self, addr):
        for i in range(self._avoids_list.count()):
            item = self._avoids_list.item(i)  # type: QListWidgetItem
            if int(item.text(), 16) == addr:
                # deduplicate
                return

        item = QListWidgetItem("%#x" % addr)
        item.setData(Qt.CheckStateRole, Qt.Checked)

        self._avoids_list.addItem(item)

    #
    # Initialization
    #

    def _init_widgets(self):
        tab = QTabWidget()

        self._init_simgrs_tab(tab)
        self._init_settings_tab(tab)
        self._init_avoids_tab(tab)

        layout = QVBoxLayout()
        layout.addWidget(tab)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    def _init_simgrs_tab(self, tab):
        # simgrs list

        simgrs_label = QLabel(self)
        simgrs_label.setText('Simulation Manager')

        simgrs_list = QComboBox(self)
        self._simgrs_list = simgrs_list
        simgrs_list.currentIndexChanged.connect(self._on_simgr_selection)

        pg_layout = QHBoxLayout()
        pg_layout.addWidget(simgrs_label)
        pg_layout.addWidget(simgrs_list)

        # simulation manager information
        viewer = QSimulationManagerViewer(self.simgr)
        self._simgr_viewer = viewer
        viewer.currentItemChanged.connect(self._on_state_selection)

        #
        # Buttons
        #

        # step button
        step_button = QPushButton()
        step_button.setText('Step actives')
        step_button.released.connect(self._on_step_clicked)

        # step until branch
        step_until_branch_button = QPushButton('Step actives until branch')
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

        simgrs_layout = QVBoxLayout()
        simgrs_layout.addLayout(pg_layout)
        simgrs_layout.addWidget(viewer)
        simgrs_layout.addLayout(buttons_layout)

        frame = QFrame()
        frame.setLayout(simgrs_layout)

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
        if not self.simgr.am_none():
            self.instance.add_job(SimgrStepJob.create(self.simgr.am_obj, until_branch=False))

    def _on_step_until_branch_clicked(self):
        if not self.simgr.am_none():
            self.instance.add_job(SimgrStepJob.create(self.simgr.am_obj, until_branch=True))

    def _on_explore_clicked(self):
        if not self.simgr.am_none():
            def _step_callback(simgr):
                if self._oneactive_checkbox.isChecked():
                    self._filter_actives(simgr, events=False)
                return simgr

            avoids = []
            for i in range(self._avoids_list.count()):
                item = self._avoids_list.item(i)  # type: QListWidgetItem
                if item.checkState() == Qt.Checked:
                    avoids.append(int(item.text(), 16))

            self.instance.add_job(SimgrExploreJob.create(
                self.simgr, avoid=avoids, find=[], step_callback=_step_callback
            ))

    def _on_simgr_selection(self):
        i = self._simgrs_list.currentIndex()
        if i != -1:
            simgr = self.simgrs[i]
        else:
            simgr = None

        if simgr != self.simgr.am_obj:
            self.simgr.am_obj = simgr
            self.simgr.am_event(src='clicked')

    def _on_state_selection(self):
        state = self._simgr_viewer.current_state()
        if state != self.state:
            self.state.am_obj = state
            self.state.am_event(src='clicked')

    def _watch_simgr(self, **kwargs):
        if kwargs.get('src') in ('clicked', 'filter_actives'):
            return
        elif kwargs.get('src') == 'job_done' and kwargs.get('job') == 'step':
            self._filter_actives(self.simgr)
        else:
            idx = self._simgrs_list.findText(self.simgr.am_obj.am_name)
            self._simgrs_list.setCurrentIndex(idx)

    def _watch_state(self, **kwargs):
        if kwargs.get('src') == 'clicked':
            return

        self._simgr_viewer.select_state(self.state.am_obj)

    def _watch_simgrs(self, **kwargs):
        self.refresh()

    #
    # Private methods
    #

    def _filter_actives(self, simgr, events=True):
        if not self._oneactive_checkbox.isChecked():
            return False
        if len(simgr.active) < 2:
            return False

        stashed = simgr.active[1:]
        simgr.stashes['stashed'].extend(stashed)
        simgr.stashes['active'] = simgr.active[:1]
        if events:
           simgr.am_event(src='filter_actives', filtered=stashed)
        return True
