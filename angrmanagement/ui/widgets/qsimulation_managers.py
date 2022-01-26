from typing import TYPE_CHECKING

from PySide2.QtWidgets import QFrame, QInputDialog, QLabel, QComboBox, QHBoxLayout, QVBoxLayout, QPushButton, \
    QCheckBox, QTabWidget, QTreeWidget, QTreeWidgetItem
from PySide2.QtCore import Qt

from ...data.jobs import SimgrStepJob, SimgrExploreJob
from ..widgets.qsimulation_manager_viewer import QSimulationManagerViewer
from ...logic.threads import gui_thread_schedule

if TYPE_CHECKING:
    from angr import SimState
    from typing import List


class QSimulationManagers(QFrame):
    def __init__(self, instance: 'Instance', simgr, state, parent=None):
        """
        :param instance:                The data source for this project
        :param object parent:           The parent widget.
        """
        super().__init__(parent)

        self.instance = instance
        self.simgrs = instance.simgrs
        self.simgr = simgr
        self.state = state

        self._simgrs_list = None  # type: QComboBox
        self._avoids_list = None  # type: QTreeWidget
        self._finds_list = None  # type: QTreeWidget
        self._simgr_viewer = None  # type: QSimulationManagerViewer
        self._oneactive_checkbox = None  # type: QCheckBox

        self._init_widgets()
        self.refresh()

        self.simgr.am_subscribe(self._watch_simgr)
        self.simgrs.am_subscribe(self._watch_simgrs)
        self.state.am_subscribe(self._watch_state)

    @property
    def find_addrs(self):
        return list({int(item.text(0), 16) for item in self._get_checked_items(self._finds_list)})

    @property
    def avoid_addrs(self):
        return list({int(item.text(0), 16) for item in self._get_checked_items(self._avoids_list)})

    def hideEvent(self, event):  # pylint: disable=unused-argument
        self.simgr.am_unsubscribe(self._watch_simgr)
        self.simgrs.am_unsubscribe(self._watch_simgrs)
        self.state.am_unsubscribe(self._watch_state)
        return super().destroy()

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
        self.add_address_to_list(self._avoids_list, addr)

    def add_find_address(self, addr):
        self.add_address_to_list(self._finds_list, addr)

    def remove_find_address(self, addr):
        self._remove_addr(self._finds_list, addr)

    def remove_avoid_address(self, addr):
        self._remove_addr(self._avoids_list, addr)

    @staticmethod
    def add_address_to_list(qtreelist: QTreeWidget, addr):
        for i in range(qtreelist.topLevelItemCount()):
            item = qtreelist.topLevelItem(i)  # type: QTreeWidgetItem
            if int(item.text(0), 16) == addr:
                return None # deduplicate

        item = QTreeWidgetItem(qtreelist)
        item.setText(0, "%#x" % addr)
        item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
        item.setData(0, Qt.CheckStateRole, Qt.Checked)
        return item

    #
    # Initialization
    #

    def _init_widgets(self):
        tab = QTabWidget()

        self._init_simgrs_tab(tab)
        self._init_settings_tab(tab)
        self._init_avoids_tab(tab)
        self._init_finds_tab(tab)

        layout = QVBoxLayout()
        layout.addWidget(tab)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    def select_states(self, states: 'List[SimState]'):
        stash_tree_item = self._simgr_viewer.get_stash_tree_item("active")
        states_set = set(states)
        for state_tree_item in stash_tree_item:
            if state_tree_item.state in states_set:
                state_tree_item.setSelected(True)
        stash_tree_item.setExpanded(True)

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
        avoids_list = QTreeWidget()
        avoids_list.setHeaderHidden(True)
        self._avoids_list = avoids_list

        layout = QVBoxLayout()
        layout.addWidget(avoids_list)

        import_button = QPushButton("Import List")
        import_button.clicked.connect(lambda: self._import_to_list(self._avoids_list))
        layout.addWidget(import_button)

        frame = QFrame()
        frame.setLayout(layout)

        tab.addTab(frame, 'Avoids')

        self._avoids_list.itemChanged.connect(self._on_explore_addr_changed)

    def _init_finds_tab(self, tab):
        finds_list = QTreeWidget()
        finds_list.setHeaderHidden(True)
        self._finds_list = finds_list

        layout = QVBoxLayout()
        layout.addWidget(finds_list)

        frame = QFrame()
        frame.setLayout(layout)

        import_button = QPushButton("Import List")
        import_button.clicked.connect(lambda: self._import_to_list(self._finds_list))
        layout.addWidget(import_button)

        tab.addTab(frame, 'Finds')

        self._finds_list.itemChanged.connect(self._on_explore_addr_changed)

    #
    # Event handlers
    #

    def _on_step_clicked(self):
        if not self.simgr.am_none:
            self.instance.add_job(SimgrStepJob.create(self.simgr.am_obj, until_branch=False,
                step_callback=self.instance.workspace.plugins.step_callback))

    def _on_step_until_branch_clicked(self):
        if not self.simgr.am_none:
            self.instance.add_job(SimgrStepJob.create(self.simgr.am_obj, until_branch=True,
                step_callback=self.instance.workspace.plugins.step_callback))

    def _on_explore_clicked(self):
        if not self.simgr.am_none:
            def _step_callback(simgr):
                self.instance.workspace.plugins.step_callback(simgr)
                if self._oneactive_checkbox.isChecked():
                    self._filter_actives(simgr, events=False)
                gui_thread_schedule(lambda: self.simgr.am_event(src="post_step"))
                return simgr

            self.instance.add_job(SimgrExploreJob.create(
                self.simgr, avoid=self.avoid_addrs, find=self.find_addrs, step_callback=_step_callback
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
        if kwargs.get('src') in ('clicked', 'filter_actives', "post_step"):
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

    def _watch_simgrs(self, **kwargs):  # pylint: disable=unused-argument
        self.refresh()

    def _on_explore_addr_changed(self, item: QTreeWidgetItem): #pylint: disable=unused-argument
        """Refresh the disassembly view when an address in the 'avoids' or 'finds' tab is toggled. Ensures that
        annotations next to instructions are updated."""
        view_manager = self.instance.workspace.view_manager
        if len(view_manager.views_by_category['disassembly']) == 1:
            view = view_manager.first_view_in_category('disassembly')
        else:
            view = view_manager.current_view_in_category('disassembly')
        if view is not None:
            view.refresh()

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


    @staticmethod
    def _get_checked_items(qlist: QTreeWidget):
        items = []
        for i in range(qlist.topLevelItemCount()):
            item = qlist.topLevelItem(i)
            if item.checkState(0) == Qt.Checked:
                items.append(item)
                for j in range(item.childCount()):
                    sub_item = item.child(j)
                    if sub_item.checkState(0) == Qt.Checked:
                        items.append(sub_item)
        return items

    def _import_to_list(self,qlist: QTreeWidget):
        text, ok = QInputDialog.getMultiLineText(self,"Input Address List","Address in hex (one address each line):","")
        if not ok:
            return
        for line in text.splitlines(keepends=False):
            try:
                addr = int(line, 16)
                self.add_address_to_list(qlist, addr)
            except ValueError as e: #pylint: disable=unused-variable
                pass

    @staticmethod
    def _remove_addr(qlist: QTreeWidget, addr):
        for i in range(qlist.topLevelItemCount()):
            qitem = qlist.topLevelItem(i)
            if int(qitem.text(0), 16) == addr:
                qlist.takeTopLevelItem(i)
                return
