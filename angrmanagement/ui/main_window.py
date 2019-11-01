import pickle
import os

from PySide2.QtWidgets import QMainWindow, QTabWidget, QFileDialog, QProgressBar, QMessageBox, QSplitter, QHBoxLayout, QWidget, QShortcut, QLabel
from PySide2.QtGui import QResizeEvent, QIcon, QDesktopServices, QKeySequence
from PySide2.QtCore import Qt, QSize, QEvent, QTimer, QUrl

import angr
import cle
try:
    import archr
    import keystone
except ImportError as e:
    archr = None
    keystone = None

from ..plugins import PluginManager
from ..logic import GlobalInfo
from ..data.instance import Instance
from ..data.jobs.loading import LoadTargetJob, LoadBinaryJob
from .menus.file_menu import FileMenu
from .menus.analyze_menu import AnalyzeMenu
from .menus.help_menu import HelpMenu
from .menus.view_menu import ViewMenu
from .menus.plugin_menu import PluginMenu
from .menus.sync_menu import SyncMenu
from ..config import IMG_LOCATION
from .workspace import Workspace
from .dialogs.load_plugins import LoadPlugins, LoadPluginsError
from .dialogs.load_docker_prompt import LoadDockerPrompt, LoadDockerPromptError
from .dialogs.new_state import NewState
from .dialogs.sync_config import SyncConfig
from .dialogs.about import LoadAboutDialog
from .toolbars import StatesToolbar, AnalysisToolbar, FileToolbar
from ..utils import has_binsync


class MainWindow(QMainWindow):
    """
    The main window of angr management.
    """
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)

        icon_location = os.path.join(IMG_LOCATION, 'angr.png')
        self.setWindowIcon(QIcon(icon_location))

        GlobalInfo.main_window = self

        # initialization
        self.caption = "angr Management"
        self.setMinimumSize(QSize(400, 400))
        self.setDockNestingEnabled(True)

        self.workspace = None
        self.central_widget = None
        self.central_widget2 = None
        self._plugin_mgr = None  # type: PluginManager

        self._file_toolbar = None  # type: FileToolbar
        self._states_toolbar = None  # type: StatesToolbar
        self._analysis_toolbar = None  # type: AnalysisToolbar
        self._progressbar = None  # type: QProgressBar
        self._load_binary_dialog = None

        self._status = ""
        self._progress = None

        self.defaultWindowFlags = None

        # menus
        self._file_menu = None
        self._analyze_menu = None
        self._view_menu = None
        self._help_menu = None
        self._plugin_menu = None
        self._sync_menu = None

        self._init_toolbars()
        self._init_statusbar()
        self._init_workspace()
        self._init_shortcuts()
        self._init_menus()
        self._init_plugins()

        self.showMaximized()

        # I'm ready to show off!
        self.show()

        self.status = "Ready."

    def sizeHint(self, *args, **kwargs):
        return QSize(1200, 800)

    #
    # Properties
    #

    @property
    def caption(self):
        return self.getWindowTitle()

    @caption.setter
    def caption(self, v):
        self.setWindowTitle(v)

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, v):
        self._status = v

        self.statusBar().showMessage(v)

    @property
    def progress(self):
        return self._progress

    @progress.setter
    def progress(self, v):
        self._progress = v
        self._progressbar.show()
        self._progressbar.setValue(v)

    #
    # Dialogs
    #

    def _open_mainfile_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open a binary", ".",
                                                   "All executables (*);;Windows PE files (*.exe);;Core Dumps (*.core);;angr database (*.adb)",
                                                   )
        return file_path

    def _pick_image_dialog(self):
        try:
            prompt = LoadDockerPrompt()
        except LoadDockerPromptError:
            return
        if prompt.exec_() == 0:
            return # User canceled
        return prompt.textValue()

    def open_load_plugins_dialog(self):
        try:
            dlg = LoadPlugins(self._plugin_mgr)
            dlg.setModal(True)
            dlg.exec_()

        except LoadPluginsError:
            pass

    def open_newstate_dialog(self):
        new_state_dialog = NewState(self.workspace.instance, parent=self)
        new_state_dialog.exec_()

    def open_doc_link(self):
        QDesktopServices.openUrl(QUrl("https://docs.angr.io/", QUrl.TolerantMode))

    def open_sync_config_dialog(self):
        if self.workspace.instance.project is None:
            # project does not exist yet
            return

        sync_config = SyncConfig(self.workspace.instance, parent=self)
        sync_config.exec_()

    def open_about_dialog(self):
        dlg = LoadAboutDialog()
        dlg.exec_()

    #
    # Widgets
    #

    def _init_statusbar(self):

        self._progressbar = QProgressBar()

        self._progressbar.setMinimum(0)
        self._progressbar.setMaximum(100)
        self._progressbar.hide()

        self.statusBar().addPermanentWidget(self._progressbar)

    def _init_toolbars(self):

        self._file_toolbar = FileToolbar(self)
        self._states_toolbar = StatesToolbar(self)
        self._analysis_toolbar = AnalysisToolbar(self)

        self.addToolBar(Qt.TopToolBarArea, self._file_toolbar.qtoolbar())
        self.addToolBar(Qt.TopToolBarArea, self._states_toolbar.qtoolbar())
        self.addToolBar(Qt.TopToolBarArea, self._analysis_toolbar.qtoolbar())

    #
    # Menus
    #

    def _init_menus(self):
        self._file_menu = FileMenu(self)
        self._analyze_menu = AnalyzeMenu(self)
        self._view_menu = ViewMenu(self)
        self._help_menu = HelpMenu(self)
        self._plugin_menu = PluginMenu(self)

        self.menuBar().addMenu(self._file_menu.qmenu())
        self.menuBar().addMenu(self._view_menu.qmenu())
        self.menuBar().addMenu(self._analyze_menu.qmenu())
        if has_binsync():
            self._sync_menu = SyncMenu(self)
            self.menuBar().addMenu(self._sync_menu.qmenu())
            def on_load(**kwargs):
                self._sync_menu.action_by_key("config").enable()
            self.workspace.instance._project_container.am_subscribe(on_load)
        self.menuBar().addMenu(self._plugin_menu.qmenu())
        self.menuBar().addMenu(self._help_menu.qmenu())

    #
    # Workspace
    #

    def _init_workspace(self):
        """
        Initialize workspace

        :return:    None
        """

        self.central_widget_main = QSplitter(Qt.Horizontal)
        self.setCentralWidget(self.central_widget_main)
        self.central_widget = QMainWindow()
        self.central_widget2 = QMainWindow()
        self.central_widget_main.addWidget(self.central_widget)
        self.central_widget_main.addWidget(self.central_widget2)
        wk = Workspace(self, Instance())
        self.workspace = wk
        self.workspace.view_manager.tabify_center_views()
        self.central_widget.setTabPosition(Qt.RightDockWidgetArea, QTabWidget.North)
        self.central_widget2.setTabPosition(Qt.LeftDockWidgetArea, QTabWidget.North)

    #
    # Shortcuts
    #

    def _init_shortcuts(self):
        """
        Initialize shortcuts

        :return:    None
        """

        center_dockable_views = self.workspace.view_manager.get_center_views()
        for i in range(1, len(center_dockable_views)+1):
            QShortcut(QKeySequence('Ctrl+'+str(i)), self, center_dockable_views[i-1].raise_)

        # Raise the DisassemblyView after everything has initialized
        center_dockable_views[0].raise_()

    #
    # PluginManager
    #

    def _init_plugins(self):
        self._plugin_mgr = PluginManager(self.workspace, autoload=True)


    #
    # Event
    #

    def resizeEvent(self, event):
        """

        :param QResizeEvent event:
        :return:
        """

        self._recalculate_view_sizes(event.oldSize())

    def closeEvent(self, event):
        self._plugin_mgr.stop_all_plugin_threads()
        event.accept()

    def event(self, event):

        if event.type() == QEvent.User:
            # our event callback

            try:
                event.result = event.execute()
            except Exception as e:
                event.exception = e
            event.event.set()

            return True

        return super(MainWindow, self).event(event)

    #
    # Actions
    #

    def reload(self):
        self.workspace.reload()

    def open_file_button(self):
        file_path = self._open_mainfile_dialog()
        self.load_file(file_path)

    def open_docker_button(self):
        required = {
            'archr: git clone https://github.com/angr/archr && cd archr && pip install -e .':archr,
            'keystone: pip install --no-binary keystone-engine keystone-engine':keystone
            }
        is_missing = [ key for key, value in required.items() if value is None ]
        if len(is_missing) > 0:
            req_msg = 'You need to install the following:\n\n\t' + '\n\t'.join(is_missing)
            req_msg += '\n\nInstall them to enable this functionality.'
            req_msg += '\nRelaunch angr-management after install.'
            QMessageBox(self).critical(None, 'Dependency error', req_msg)
            return

        img_name = self._pick_image_dialog()
        if img_name is None:
            return
        target = archr.targets.DockerImageTarget(img_name, target_path=None)
        self.workspace.instance.add_job(LoadTargetJob(target))
        self.workspace.instance.set_image(img_name)

    def load_file(self, file_path):
        if os.path.isfile(file_path):
            if file_path.endswith(".adb"):
                self.load_database(file_path)
            else:
                self.workspace.instance.add_job(LoadBinaryJob(file_path))

    def save_database(self):
        if self.workspace.instance.database_path is None:
            self.save_database_as()
        else:
            self._save_database(self.workspace.instance.database_path)

    def save_database_as(self):

        # Open File window
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save angr database", ".",
            "angr databases (*.adb)",
        )

        if not file_path.endswith(".adb"):
            file_path = file_path + ".adb"

        self._save_database(file_path)

    def quit(self):
        self.close()

    def run_variable_recovery(self):
        self.workspace.view_manager.first_view_in_category('disassembly').variable_recovery_flavor = 'accurate'

    def run_induction_variable_analysis(self):
        self.workspace.view_manager.first_view_in_category('disassembly').run_induction_variable_analysis()

    def decompile_current_function(self):
        if self.workspace is not None:
            self.workspace.decompile_current_function()

    def interact(self):
        self.workspace.interact_program(self.workspace.instance.img_name)

    def setup_sync(self):
        self.open_sync_config_dialog()

    #
    # Other public methods
    #

    def progress_done(self):
        self._progress = None
        self._progressbar.hide()

    #
    # Private methods
    #

    def _load_database(self, file_path):
        with open(file_path, "rb") as o:
            p,cfg,cfb = pickle.load(o)
        self.workspace.instance.project = p
        self.workspace.instance.cfg = cfg
        self.workspace.instance.cfb = cfb
        self.workspace.reload()
        self.workspace.on_cfg_generated()
        self.workspace.instance.database_path = file_path
        print("DATABASE %s LOADED" % file_path)

    def _save_database(self, file_path):
        with open(file_path, "wb") as o:
            pickle.dump((self.workspace.instance.project, self.workspace.instance.cfg, self.workspace.instance.cfb), o)
        self.workspace.instance.database_path = file_path
        print("DATABASE %s SAVED" % file_path)

    def _recalculate_view_sizes(self, old_size):
        adjustable_dockable_views = [dock for dock in self.workspace.view_manager.docks
                                     if dock.widget().default_docking_position in ('left', 'bottom', )]

        if not adjustable_dockable_views:
            return

        for dock in adjustable_dockable_views:
            widget = dock.widget()

            if old_size.width() < 0:
                dock.old_size = widget.sizeHint()
                continue

            if old_size != self.size():
                # calculate the width ratio

                if widget.default_docking_position == 'left':
                    # we want to adjust the width
                    ratio = widget.old_width * 1.0 / old_size.width()
                    new_width = int(self.width() * ratio)
                    widget.width_hint = new_width
                    widget.updateGeometry()
                elif widget.default_docking_position == 'bottom':
                    # we want to adjust the height
                    ratio = widget.old_height * 1.0 / old_size.height()
                    new_height = int(self.height() * ratio)
                    widget.height_hint = new_height
                    widget.updateGeometry()

                dock.old_size = widget.size()

    def _resize_dock_widget(self, dock_widget, new_width, new_height):

        original_size = dock_widget.size()
        original_min = dock_widget.minimumSize()
        original_max = dock_widget.maximumSize()

        dock_widget.resize(new_width, new_height)

        if new_width != original_size.width():
            if original_size.width() > new_width:
                dock_widget.setMaximumWidth(new_width)
            else:
                dock_widget.setMinimumWidth(new_width)

        if new_height != original_size.height():
            if original_size.height() > new_height:
                dock_widget.setMaximumHeight(new_height)
            else:
                dock_widget.setMinimumHeight(new_height)

        dock_widget.original_min = original_min
        dock_widget.original_max = original_max

        QTimer.singleShot(1, dock_widget.restore_original_size)
