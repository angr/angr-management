# pylint:disable=no-self-use
import os
import logging
import pickle
import sys
import time
from functools import partial
from typing import Optional, TYPE_CHECKING

from PySide6.QtWidgets import QMainWindow, QTabWidget, QFileDialog, QProgressBar, QProgressDialog
from PySide6.QtWidgets import QMessageBox, QTabBar
from PySide6.QtGui import QIcon, QDesktopServices, QKeySequence, QShortcut
from PySide6.QtCore import Qt, QSize, QEvent, QUrl

import angr
import angr.flirt

try:
    from angr.angrdb import AngrDB
except ImportError:
    AngrDB = None  # type: Optional[type]

try:
    import archr
    import keystone
except ImportError:
    archr = None
    keystone = None

from ..daemon import daemon_exists, run_daemon_process, daemon_conn
from ..daemon.client import ClientService
from ..logic import GlobalInfo
from ..data.instance import Instance
from ..data.library_docs import LibraryDocs
from ..data.jobs.loading import LoadTargetJob, LoadBinaryJob, LoadAngrDBJob
from ..data.jobs import DependencyAnalysisJob
from ..config import IMG_LOCATION, Conf, save_config
from ..utils.io import isurl, download_url
from ..utils.env import is_pyinstaller, app_root
from ..errors import InvalidURLError, UnexpectedStatusCodeError
from .menus.file_menu import FileMenu
from .menus.analyze_menu import AnalyzeMenu
from .menus.help_menu import HelpMenu
from .menus.view_menu import ViewMenu
from .menus.plugin_menu import PluginMenu
from .workspace import Workspace
from .dialogs.load_plugins import LoadPlugins
from .dialogs.load_docker_prompt import LoadDockerPrompt, LoadDockerPromptError
from .dialogs.new_state import NewState
from .dialogs.about import LoadAboutDialog
from .dialogs.preferences import Preferences
from .toolbars import FileToolbar, DebugToolbar
from .toolbar_manager import ToolbarManager

if TYPE_CHECKING:
    from PySide6.QtWidgets import QApplication

_l = logging.getLogger(name=__name__)


class MainWindow(QMainWindow):
    """
    The main window of angr management.
    """

    def __init__(self, app: Optional['QApplication'] = None, parent=None, show=True, use_daemon=False):
        super().__init__(parent)

        icon_location = os.path.join(IMG_LOCATION, 'angr.png')
        self.setWindowIcon(QIcon(icon_location))

        GlobalInfo.main_window = self
        self.shown_at_start = show

        # initialization
        self.setMinimumSize(QSize(400, 400))
        self.setDockNestingEnabled(True)

        self.app: Optional['QApplication'] = app
        self.workspace: Workspace = None
        self.central_widget: QMainWindow = None

        self.toolbar_manager: ToolbarManager = ToolbarManager(self)
        self._progressbar = None  # type: QProgressBar
        self._progress_dialog = None # type: QProgressDialog

        self.defaultWindowFlags = None

        # menus
        self._file_menu = None  # FileMenu
        self._analyze_menu = None
        self._view_menu = None
        self._help_menu = None
        self._plugin_menu = None

        self._init_statusbar()
        self._init_workspace()
        self._init_toolbars()
        self._init_menus()
        self._init_plugins()
        self._init_library_docs()
        self._init_url_scheme_handler()

        self.workspace.plugins.on_workspace_initialized(self)

        self._init_shortcuts()
        self._init_flirt_signatures()

        self._run_daemon(use_daemon=use_daemon)

        # I'm ready to show off!
        if show:
            self.showMaximized()
            self.windowHandle().screenChanged.connect(self.on_screen_changed)
            self.show()

        self.status = "Ready."

    def sizeHint(self, *args, **kwargs):  # pylint: disable=unused-argument,no-self-use
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

    #
    # Dialogs
    #

    def open_mainfile_dialog(self):
        # pylint: disable=assigning-non-slot
        # https://github.com/PyCQA/pylint/issues/3793
        file_path, _ = QFileDialog.getOpenFileName(self, "Open a binary", Conf.last_used_directory,
                                                   "All executables (*);;"
                                                   "Windows PE files (*.exe);;"
                                                   "Core Dumps (*.core);;"
                                                   "angr database (*.adb)",
                                                   )
        Conf.last_used_directory = os.path.dirname(file_path)
        return file_path

    def _pick_image_dialog(self):
        try:
            prompt = LoadDockerPrompt(parent=self)
        except LoadDockerPromptError:
            return None
        if prompt.exec_() == 0:
            return None  # User canceled
        return prompt.textValue()

    def open_load_plugins_dialog(self):
        dlg = LoadPlugins(self.workspace.plugins)
        dlg.setModal(True)
        dlg.exec_()

    def open_newstate_dialog(self):
        if self.workspace.main_instance.project.am_none:
            QMessageBox.critical(self,
                                 "Cannot create new states",
                                 "Please open a binary to analyze first.")
            return
        new_state_dialog = NewState(self.workspace.main_instance, parent=self, create_simgr=True)
        new_state_dialog.exec_()

    def open_doc_link(self):
        QDesktopServices.openUrl(QUrl("https://docs.angr.io/", QUrl.TolerantMode))

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

        self._progress_dialog = QProgressDialog("Waiting...", "Cancel", 0, 100, self)
        self._progress_dialog.setAutoClose(False)
        self._progress_dialog.setWindowFlags(self._progress_dialog.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self._progress_dialog.setModal(True)
        self._progress_dialog.setMinimumDuration(2**31 - 1)
        def on_cancel():
            if self.workspace is None:
                return
            for job in self.workspace.main_instance.jobs:
                if job.blocking:
                    job.keyboard_interrupt()
                    break
        self._progress_dialog.canceled.connect(on_cancel)
        self._progress_dialog.close()

    def _init_toolbars(self):
        for cls in (FileToolbar, DebugToolbar):
            self.toolbar_manager.show_toolbar_by_class(cls)

    #
    # Menus
    #

    def _init_menus(self):
        self._file_menu = FileMenu(self)
        self._analyze_menu = AnalyzeMenu(self)
        self._view_menu = ViewMenu(self)
        self._help_menu = HelpMenu(self)
        self._plugin_menu = PluginMenu(self)

        for path in Conf.recent_files:
            self._file_menu.add_recent(path)

        # TODO: Eventually fix menu bars to have native support on MacOS
        # if on a Mac, don't use the native menu bar (bug mitigation from QT)
        if sys.platform == 'darwin':
            self.menuBar().setNativeMenuBar(False)

        self.menuBar().addMenu(self._file_menu.qmenu())
        self.menuBar().addMenu(self._view_menu.qmenu())
        self.menuBar().addMenu(self._analyze_menu.qmenu())
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
        self.central_widget = QMainWindow()
        self.setCentralWidget(self.central_widget)
        wk = Workspace(self, Instance())
        self.workspace = wk
        self.workspace.view_manager.tabify_center_views()
        self.central_widget.setTabPosition(Qt.RightDockWidgetArea, QTabWidget.North)
        self.central_widget.setDockNestingEnabled(True)

        def set_caption(**kwargs):  # pylint: disable=unused-argument
            if self.workspace.main_instance.project.am_none:
                self.caption = ''
            elif self.workspace.main_instance.project.filename is None:
                self.caption = "Loaded from stream"
            else:
                self.caption = os.path.basename(self.workspace.main_instance.project.filename)

        self.workspace.main_instance.project.am_subscribe(set_caption)

        self.tab = self.central_widget.findChild(QTabBar)
        self.tab.tabBarClicked.connect(self.on_center_tab_clicked)

    #
    # Shortcuts
    #

    def interrupt_current_job(self):
        self.workspace.main_instance.interrupt_current_job()

    def _init_shortcuts(self):
        """
        Initialize shortcuts

        :return:    None
        """

        center_dockable_views = self.workspace.view_manager.get_center_views()
        for i in range(1, len(center_dockable_views) + 1):
            QShortcut(QKeySequence('Ctrl+' + str(i)), self, center_dockable_views[i - 1].raise_)

        QShortcut(QKeySequence("Ctrl+I"), self, self.interrupt_current_job)

        # Raise the DisassemblyView after everything has initialized
        center_dockable_views[0].raise_()

        # Toggle exec breakpoint
        QShortcut(QKeySequence(Qt.Key_F2), self, self.workspace.toggle_exec_breakpoint)

        # Single step
        QShortcut(QKeySequence(Qt.Key_F7), self, self.workspace.step_forward)

        # Run
        QShortcut(QKeySequence(Qt.Key_F9), self, self.workspace.continue_forward)

    #
    # Plugins
    #

    def _init_plugins(self):
        self.workspace.plugins.discover_and_initialize_plugins()

    #
    # FLIRT Signatures
    #

    def _init_flirt_signatures(self):
        if Conf.flirt_signatures_root:
            # if it's a relative path, it's relative to the angr-management package
            if os.path.isabs(Conf.flirt_signatures_root):
                flirt_signatures_root = Conf.flirt_signatures_root
            else:
                if is_pyinstaller():
                    flirt_signatures_root = os.path.join(app_root(), Conf.flirt_signatures_root)
                else:
                    # when running as a Python package, we should use the git submodule, which is on the same level
                    # with (instead of inside) the angrmanagement module directory.
                    flirt_signatures_root = os.path.join(app_root(), "..", Conf.flirt_signatures_root)
            flirt_signatures_root = os.path.normpath(flirt_signatures_root)
            _l.info("Loading FLIRT signatures from %s.", flirt_signatures_root)
            angr.flirt.load_signatures(flirt_signatures_root)

    #
    # Library docs
    #

    def _init_library_docs(self):
        GlobalInfo.library_docs = LibraryDocs()
        if Conf.library_docs_root:
            GlobalInfo.library_docs.load_func_docs(Conf.library_docs_root)

    #
    # Daemon
    #

    def _run_daemon(self, use_daemon=None):

        if use_daemon is None:
            # Load it from the configuration file
            use_daemon = Conf.use_daemon

        if not use_daemon:
            return

        # connect to daemon (if there is one)
        if not daemon_exists():
            print("[+] Starting a new daemon.")
            run_daemon_process()
            time.sleep(0.2)
        else:
            print("[+] Connecting to an existing angr management daemon.")

        while True:
            try:
                GlobalInfo.daemon_conn = daemon_conn(service=ClientService)
            except ConnectionRefusedError:
                print("[-] Connection failed... try again.")
                time.sleep(0.4)
                continue
            print("[+] Connected to daemon.")
            break

        from rpyc import BgServingThread  # pylint:disable=import-outside-toplevel
        _ = BgServingThread(GlobalInfo.daemon_conn)

    #
    # URL scheme handler setup
    #

    def _init_url_scheme_handler(self):
        # URL scheme
        from ..logic.url_scheme import AngrUrlScheme  # pylint:disable=import-outside-toplevel

        scheme = AngrUrlScheme()
        registered, _ = scheme.is_url_scheme_registered()
        supported = scheme.is_url_scheme_supported()
        checrs_plugin = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")
        if checrs_plugin is None:
            return

        if not registered and supported:
            btn = QMessageBox.question(None, "Setting up angr URL scheme",
                                       "angr URL scheme allows \"deep linking\" from browsers and other applications "
                                       "by registering the angr:// protocol to the current user. Do you want to "
                                       "register it? You may unregister at any "
                                       "time in Preferences.",
                                       defaultButton=QMessageBox.Yes)
            if btn == QMessageBox.Yes:
                try:
                    AngrUrlScheme().register_url_scheme()
                except (ValueError, FileNotFoundError) as ex:
                    QMessageBox.warning(None, "Error in registering angr URL scheme",
                                        "Failed to register the angr URL scheme.\n"
                                        "The following exception occurred:\n"
                                        + str(ex))

    #
    # Event
    #

    def closeEvent(self, event):

        # Ask if the user wants to save things
        if self.workspace.main_instance is not None \
                and not self.workspace.main_instance.project.am_none \
                and self.shown_at_start:
            msgbox = QMessageBox()
            msgbox.setWindowTitle("Save database")
            msgbox.setText("angr management is about to exit. Do you want to save the database?")
            msgbox.setIcon(QMessageBox.Question)
            msgbox.setWindowIcon(self.windowIcon())
            msgbox.setStandardButtons(QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
            msgbox.setDefaultButton(QMessageBox.Yes)
            r = msgbox.exec_()

            if r == QMessageBox.Cancel:
                event.ignore()
                return
            elif r == QMessageBox.Yes:
                save_r = self.save_database()
                if not save_r:
                    # failed to save the database
                    event.ignore()
                    return

        for plugin in list(self.workspace.plugins.active_plugins.values()):
            self.workspace.plugins.deactivate_plugin(plugin)
        event.accept()

    def event(self, event):

        if event.type() == QEvent.User:
            # our event callback

            try:
                event.result = event.execute()
            except Exception as ex:  # pylint:disable=broad-except
                event.exception = ex
            event.event.set()

            return True

        return super().event(event)

    def on_screen_changed(self, screen):
        """
        When changing from one screen to another, ask disassembly views to refresh in case the DPI is changed.
        """
        self.workspace.current_screen.am_obj = screen
        self.workspace.current_screen.am_event()

    def on_center_tab_clicked(self, index):
        self.workspace.view_manager.handle_center_tab_click(index)

    #
    # Actions
    #

    def reload(self):
        self.workspace.reload()

    def open_file_button(self):
        file_path = self.open_mainfile_dialog()
        if not file_path:
            return
        self.load_file(file_path)

    def open_trace_file_button(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open a trace file", Conf.last_used_directory,
                                                   "All files (*);;"
                                                   "Trace files (*.trace);;",
                                                   )
        Conf.last_used_directory = os.path.dirname(file_path)
        if not file_path:
            return
        self.load_trace_file(file_path)

    def open_docker_button(self):
        required = {
            'archr: git clone https://github.com/angr/archr && cd archr && pip install -e .': archr,
            'keystone: pip install --no-binary keystone-engine keystone-engine': keystone
        }
        is_missing = [key for key, value in required.items() if value is None]
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
        self.workspace.main_instance.add_job(LoadTargetJob(target))
        self.workspace.main_instance.img_name = img_name

    def load_trace_file(self, file_path):
        if isurl(file_path):
            QMessageBox.critical(self,
                                 "Unsupported Action",
                                 "Downloading trace files is not yet supported."
                                 "Please specify a path to a file on disk.")
        else:
            # File
            if os.path.isfile(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        loaded_sim_state = pickle.load(f)
                        analysis_params = {
                            'end_state': loaded_sim_state,
                            'start_addr': None,
                            'end_addr': None,
                            'block_addrs': None,
                        }
                        self.workspace.view_data_dependency_graph(analysis_params)
                    self._recent_file(file_path)
                except pickle.PickleError:
                    QMessageBox.critical(self,
                                         "Unable to load trace file",
                                         "Trace file must contain a serialized SimState.")
            else:
                QMessageBox.critical(self,
                                     "File not found",
                                     f"angr management cannot open file {file_path}. "
                                     "Please make sure that the file exists.")

    def load_file(self, file_path):

        if not isurl(file_path):
            # file
            if os.path.isfile(file_path):
                if file_path.endswith(".trace"):
                    self.workspace.load_trace_from_path(file_path)
                    return

                self.workspace.main_instance.binary_path = file_path
                self.workspace.main_instance.original_binary_path = file_path
                if file_path.endswith(".adb"):
                    self._load_database(file_path)
                else:
                    self._recent_file(file_path)
                    self.workspace.main_instance.add_job(LoadBinaryJob(file_path))
            else:
                QMessageBox.critical(self,
                                     "File not found",
                                     f"angr management cannot open file {file_path}. "
                                     "Please make sure that the file exists.")
        else:
            # url
            r = QMessageBox.question(self,
                                     "Downloading a file",
                                     f"Do you want to download a file from {file_path} and open it in angr management?",
                                     defaultButton=QMessageBox.Yes)
            if r == QMessageBox.Yes:
                try:
                    target_path = download_url(file_path, parent=self, to_file=True, file_path=None)
                except InvalidURLError:
                    QMessageBox.critical(self,
                                         "Downloading failed",
                                         "angr management failed to download the file. The URL is invalid.")
                    return
                except UnexpectedStatusCodeError as ex:
                    QMessageBox.critical(self,
                                         "Downloading failed",
                                         "angr management failed to retrieve the header of the file. "
                                         f"The HTTP request returned an unexpected status code {ex.status_code}.")
                    return

                if target_path:
                    # open the file - now it's a local file
                    self.workspace.main_instance.binary_path = target_path
                    self.workspace.main_instance.original_binary_path = file_path
                    self.load_file(target_path)

    def load_database(self):
        # Open File window
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load angr database", ".",
            "angr databases (*.adb)",
        )

        if not file_path:
            return

        self._load_database(file_path)

    def save_database(self):
        if self.workspace.main_instance is None or self.workspace.main_instance.project.am_none:
            return True

        if self.workspace.main_instance.database_path is None:
            return self.save_database_as()
        else:
            return self._save_database(self.workspace.main_instance.database_path)

    def save_database_as(self):

        if self.workspace.main_instance is None or self.workspace.main_instance.project.am_none:
            return False

        default_database_path = self.workspace.main_instance.database_path
        if default_database_path is None:
            default_database_path = os.path.normpath(self.workspace.main_instance.project.filename) + ".adb"

        # Open File window
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save angr database", default_database_path,
            "angr databases (*.adb)",
        )

        if not file_path:
            return False

        if not file_path.endswith(".adb"):
            file_path = file_path + ".adb"

        return self._save_database(file_path)

    def load_trace(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load trace", ".", "bintrace (*.trace)")
        if not file_path:
            return
        self.workspace.load_trace_from_path(file_path)

    def preferences(self):
        pref = Preferences(self.workspace, parent=self)
        pref.exec_()

    def quit(self):
        self.close()

    def run_variable_recovery(self):
        self.workspace._get_or_create_disassembly_view().variable_recovery_flavor = 'accurate'

    def run_induction_variable_analysis(self):
        self.workspace._get_or_create_disassembly_view().run_induction_variable_analysis()

    def run_dependency_analysis(self, func_addr: Optional[int] = None, func_arg_idx: Optional[int] = None):
        if self.workspace is None or self.workspace.main_instance is None:
            return
        dep_analysis_job = DependencyAnalysisJob(func_addr=func_addr, func_arg_idx=func_arg_idx)
        self.workspace.main_instance.add_job(dep_analysis_job)

    def run_analysis(self):
        if self.workspace:
            self.workspace.main_instance.run_analysis()

    def decompile_current_function(self):
        if self.workspace is not None:
            self.workspace.decompile_current_function()

    def view_proximity_for_current_function(self):
        if self.workspace is not None:
            self.workspace.view_proximity_for_current_function()

    def interact(self):
        self.workspace.interact_program(self.workspace.main_instance.img_name)

    #
    # Other public methods
    #

    def progress(self, status, progress):
        self.statusBar().showMessage(f'Working... {status}')
        self._progress_dialog.setLabelText(status)
        self._progressbar.show()
        self._progressbar.setValue(progress)
        self._progress_dialog.setValue(progress)

    def progress_done(self):
        self._progressbar.hide()
        self.statusBar().showMessage("Ready.")
        self._progress_dialog.hide()

    def bring_to_front(self):
        self.setWindowState((self.windowState() & ~Qt.WindowMinimized) | Qt.WindowActive)
        self.activateWindow()
        self.raise_()

    #
    # Private methods
    #

    def _recent_file(self, file_path):
        file_path = os.path.abspath(file_path)
        self._file_menu.add_recent(file_path)
        Conf.recent_file(file_path)
        save_config()

    def _load_database(self, file_path: str):

        if AngrDB is None:
            QMessageBox.critical(None, 'Error',
                                 'AngrDB is not enabled. Maybe you do not have SQLAlchemy installed?')
            return


        other_kbs = {}
        extra_info = {}

        job = LoadAngrDBJob(file_path, ["global", "pseudocode_variable_kb"], other_kbs=other_kbs, extra_info=extra_info)
        job._on_finish = partial(self._on_load_database_finished, job)
        self.workspace.main_instance.add_job(job)

    def _on_load_database_finished(self, job: LoadAngrDBJob):
        proj = job.project

        if proj is None:
            return

        self._recent_file(job.file_path)

        cfg = proj.kb.cfgs['CFGFast']
        cfb = proj.analyses.CFB()  # it will load functions from kb

        self.workspace.main_instance.database_path = job.file_path

        self.workspace.main_instance._reset_containers()
        self.workspace.main_instance.project = proj
        self.workspace.main_instance.cfg = cfg
        self.workspace.main_instance.cfb = cfb
        if "pseudocode_variable_kb" in job.other_kbs:
            self.workspace.main_instance.pseudocode_variable_kb = job.other_kbs["pseudocode_variable_kb"]
        else:
            self.workspace.main_instance.initialize_pseudocode_variable_kb()
        self.workspace.main_instance.project.am_event(initialized=True)

        # trigger callbacks
        self.workspace.reload()
        self.workspace.on_cfg_generated()
        self.workspace.plugins.angrdb_load_entries(job.extra_info)

    def _save_database(self, file_path):
        if self.workspace.main_instance is None or self.workspace.main_instance.project.am_none:
            return False

        if AngrDB is None:
            QMessageBox.critical(None, 'Error',
                                 'AngrDB is not enabled. Maybe you do not have SQLAlchemy installed?')
            return False

        self.workspace.plugins.handle_project_save(file_path)

        angrdb = AngrDB(project=self.workspace.main_instance.project)
        extra_info = self.workspace.plugins.angrdb_store_entries()
        angrdb.dump(file_path, kbs=[
                self.workspace.main_instance.kb,
                self.workspace.main_instance.pseudocode_variable_kb,
                ],
            extra_info=extra_info,
            )

        self.workspace.main_instance.database_path = file_path
        return True
