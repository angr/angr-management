# pylint:disable=no-self-use
from __future__ import annotations

import logging
import os
import pickle
import time
from functools import partial
from typing import TYPE_CHECKING

import angr
import angr.flirt
import PySide6QtAds as QtAds
from angr.angrdb import AngrDB
from PySide6.QtCore import QEvent, QObject, QSize, Qt, QUrl
from PySide6.QtGui import QDesktopServices, QIcon, QKeySequence, QShortcut, QWindow
from PySide6.QtWidgets import (
    QFileDialog,
    QMainWindow,
    QMessageBox,
    QWidget,
)

from angrmanagement.config import IMG_LOCATION, Conf, save_config
from angrmanagement.daemon import daemon_conn, daemon_exists, run_daemon_process
from angrmanagement.daemon.client import ClientService
from angrmanagement.data.jobs import DependencyAnalysisJob
from angrmanagement.data.jobs.loading import LoadAngrDBJob, LoadBinaryJob, LoadTargetJob
from angrmanagement.data.library_docs import LibraryDocs
from angrmanagement.errors import InvalidURLError, UnexpectedStatusCodeError
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.commands import BasicCommand
from angrmanagement.logic.threads import ExecuteCodeEvent
from angrmanagement.ui.views import DisassemblyView
from angrmanagement.ui.widgets.qam_status_bar import QAmStatusBar
from angrmanagement.utils.env import app_root, is_pyinstaller
from angrmanagement.utils.io import download_url, isurl

from .dialogs.about import LoadAboutDialog
from .dialogs.command_palette import CommandPaletteDialog, GotoPaletteDialog
from .dialogs.load_docker_prompt import LoadDockerPrompt, LoadDockerPromptError
from .dialogs.load_plugins import LoadPlugins
from .dialogs.new_state import NewState
from .dialogs.preferences import Preferences
from .dialogs.welcome import WelcomeDialog
from .menus.analyze_menu import AnalyzeMenu
from .menus.file_menu import FileMenu
from .menus.help_menu import HelpMenu
from .menus.plugin_menu import PluginMenu
from .menus.view_menu import ViewMenu
from .toolbar_manager import ToolbarManager
from .toolbars import DebugToolbar, FeatureMapToolbar, FileToolbar
from .workspace import Workspace

try:
    import archr
    import keystone
except ImportError:
    archr = None
    keystone = None

if TYPE_CHECKING:
    from PySide6.QtWidgets import QApplication


_l = logging.getLogger(name=__name__)


class DockShortcutEventFilter(QObject):
    """
    Filter to support shortcuts on floating dock windows that overlap main window registered menu action shortcuts.
    """

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__()
        self._main_window: MainWindow = main_window

    def eventFilter(self, qobject, event) -> bool:
        if event.type() == QEvent.Type.KeyPress and QKeySequence(event.keyCombination()) == QKeySequence(
            "Ctrl+Shift+P"
        ):
            self._main_window.show_command_palette(qobject)
            return True
        return False


class ShiftShiftEventFilter(QObject):
    """
    Filter to catch Shift+Shift key sequence for goto-anything activation.
    """

    activation_key = Qt.Key.Key_Shift
    activation_count: int = 2
    timeout_secs: float = 1

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__()
        self._main_window: MainWindow = main_window
        self._press_count: int = 0
        self._last_press_time: float = 0
        self._did_process_qwindow_event: bool = False

    def eventFilter(self, qobject, event) -> bool:
        # Key Event propagation will begin at QWindow and continue down the widget tree. Use KeyEvent on QWindow to
        # distinguish unique key presses, then intercept KeyEvent at first QWidget the event is propagated to.

        if event.type() == QEvent.Type.KeyPress:
            if isinstance(qobject, QWindow) and qobject.modality() == Qt.WindowModality.NonModal:
                self._did_process_qwindow_event = True
                return False
            if not isinstance(qobject, QWidget) or not self._did_process_qwindow_event:
                return False
            self._did_process_qwindow_event = False

            if event.count() == 1 and event.key() == self.activation_key:
                now = time.time()
                if now - self._last_press_time >= self.timeout_secs:
                    self._press_count = 0
                self._last_press_time = now

                self._press_count += 1
                if self._press_count >= self.activation_count:
                    self._press_count = 0
                    self._main_window.show_goto_palette(qobject)
                    return True

            else:
                self._press_count = 0

        return False


class MainWindow(QMainWindow):
    """
    The main window of angr management.
    """

    def __init__(
        self, app: QApplication | None = None, parent=None, show: bool = True, use_daemon: bool = False
    ) -> None:
        super().__init__(parent)
        self.initialized = False

        icon_location = os.path.join(IMG_LOCATION, "angr.png")
        self.setWindowIcon(QIcon(icon_location))
        self.setWindowTitle("angr management")

        GlobalInfo.main_window = self
        self.shown_at_start = show

        # initialization
        self.setMinimumSize(QSize(400, 400))

        self.app: QApplication | None = app
        self.workspace: Workspace = None
        self.dock_manager: QtAds.CDockManager
        self._dock_shortcut_event_filter = DockShortcutEventFilter(self)

        self._shift_shift_event_filter = ShiftShiftEventFilter(self)
        if app:
            self.app.installEventFilter(self._shift_shift_event_filter)

        self.toolbar_manager: ToolbarManager = ToolbarManager(self)

        self.defaultWindowFlags = None

        # menus
        self._file_menu = None  # FileMenu
        self._analyze_menu = None
        self._view_menu = None
        self._help_menu = None
        self._plugin_menu = None

        self._init_workspace()

        self.status_bar = QAmStatusBar(self)

        self._init_toolbars()
        self._init_menus()
        self._init_plugins()
        self._init_library_docs()
        # self._init_url_scheme_handler()

        self._register_commands()

        self.workspace.plugins.on_workspace_initialized(self)

        self._init_shortcuts()
        self._init_flirt_signatures()

        self._run_daemon(use_daemon=use_daemon)

        # I'm ready to show off!
        if show:
            self.showMaximized()
            self.windowHandle().screenChanged.connect(self.on_screen_changed)
            self.show()

    def show_welcome_dialog(self) -> None:
        dlg = WelcomeDialog(self)
        dlg.setModal(True)
        dlg.show()

    def sizeHint(self):  # pylint: disable=no-self-use
        return QSize(1200, 800)

    #
    # Properties
    #

    @property
    def caption(self):
        return self.getWindowTitle()

    @caption.setter
    def caption(self, v) -> None:
        self.setWindowTitle(v)

    #
    # Dialogs
    #

    def open_mainfile_dialog(self):
        # pylint: disable=assigning-non-slot
        # https://github.com/PyCQA/pylint/issues/3793
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open a binary",
            self._get_recent_dir(),
            "All executables (*);;Windows PE files (*.exe);;Core Dumps (*.core);;angr database (*.adb)",
        )
        return file_path

    def _pick_image_dialog(self):
        try:
            prompt = LoadDockerPrompt(parent=self)
        except LoadDockerPromptError:
            return None
        if prompt.exec_() == 0:
            return None  # User canceled
        return prompt.textValue()

    def open_load_plugins_dialog(self) -> None:
        dlg = LoadPlugins(self.workspace.plugins)
        dlg.setModal(True)
        dlg.exec_()

    def open_newstate_dialog(self) -> None:
        if self.workspace.main_instance.project.am_none:
            QMessageBox.critical(self, "Cannot create new states", "Please open a binary to analyze first.")
            return
        new_state_dialog = NewState(self.workspace, self.workspace.main_instance, parent=self, create_simgr=True)
        new_state_dialog.exec_()

    def open_doc_link(self) -> None:
        QDesktopServices.openUrl(QUrl("https://docs.angr.io/", QUrl.ParsingMode.TolerantMode))

    def open_about_dialog(self) -> None:
        dlg = LoadAboutDialog()
        dlg.exec_()

    #
    # Widgets
    #

    def _init_toolbars(self) -> None:
        for cls in (FileToolbar, DebugToolbar, FeatureMapToolbar):
            self.toolbar_manager.show_toolbar_by_class(cls)

    #
    # Menus
    #

    def _init_menus(self) -> None:
        self._file_menu = FileMenu(self)
        self._analyze_menu = AnalyzeMenu(self)
        self._view_menu = ViewMenu(self)
        self._help_menu = HelpMenu(self)
        self._plugin_menu = PluginMenu(self)

        for path in Conf.recent_files:
            self._file_menu.add_recent(path)

        self.menuBar().addMenu(self._file_menu.qmenu())
        self.menuBar().addMenu(self._view_menu.qmenu())
        self.menuBar().addMenu(self._analyze_menu.qmenu())
        self.menuBar().addMenu(self._plugin_menu.qmenu())
        self.menuBar().addMenu(self._help_menu.qmenu())

    #
    # Workspace
    #

    def _init_workspace(self) -> None:
        """
        Initialize workspace

        :return:    None
        """
        QtAds.CDockManager.setConfigFlags(
            (
                QtAds.CDockManager.DefaultBaseConfig
                | QtAds.CDockManager.OpaqueSplitterResize
                | QtAds.CDockManager.FocusHighlighting
            )
            & ~QtAds.CDockManager.DockAreaHasUndockButton
        )
        self.dock_manager = QtAds.CDockManager(self)
        self.dock_manager.setStyleSheet("")  # Clear stylesheet overrides
        self.dock_manager.setAutoHideConfigFlags(QtAds.CDockManager.DefaultAutoHideConfig)
        self.dock_manager.createSideTabBarWidgets()
        self.setCentralWidget(self.dock_manager)
        wk = Workspace(self)
        self.workspace = wk

        def set_caption(**kwargs) -> None:  # pylint: disable=unused-argument
            if self.workspace.main_instance.project.am_none:
                self.caption = ""
            elif self.workspace.main_instance.project.filename is None:
                self.caption = "Loaded from stream"
            else:
                self.caption = os.path.basename(self.workspace.main_instance.project.filename)

        self.workspace.main_instance.project.am_subscribe(set_caption)

    #
    # Shortcuts
    #

    def _init_shortcuts(self) -> None:
        """
        Initialize shortcuts

        :return:    None
        """

        for i in range(1, 10):
            QShortcut(QKeySequence(f"Alt+{i}"), self, lambda idx=i: self._raise_view(idx - 1))
        QShortcut(QKeySequence("Alt+0"), self, lambda: self._raise_view(9))

        QShortcut(QKeySequence("Ctrl+I"), self, self.workspace.job_manager.interrupt_current_job)

        # Raise the DisassemblyView after everything has initialized
        self._raise_view(0)

        # Toggle exec breakpoint
        QShortcut(QKeySequence(Qt.Key.Key_F2), self, self.workspace.toggle_exec_breakpoint)

        # Single step
        QShortcut(QKeySequence(Qt.Key.Key_F7), self, self.workspace.step_forward)

        # Run
        QShortcut(QKeySequence(Qt.Key.Key_F9), self, self.workspace.continue_forward)

    def init_shortcuts_on_dock(self, dock_widget) -> None:
        """
        Installs an event filter on the dock widget to support floating dock global shortcuts (e.g. command palette).
        """
        dock_widget.installEventFilter(self._dock_shortcut_event_filter)

    #
    # Plugins
    #

    def _init_plugins(self) -> None:
        self.workspace.plugins.discover_and_initialize_plugins()

    #
    # FLIRT Signatures
    #

    def _init_flirt_signatures(self) -> None:
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

    def _init_library_docs(self) -> None:
        GlobalInfo.library_docs = LibraryDocs()
        if Conf.library_docs_root:
            GlobalInfo.library_docs.load_func_docs(Conf.library_docs_root)

    #
    # Daemon
    #

    def _run_daemon(self, use_daemon=None) -> None:
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

    def _init_url_scheme_handler(self) -> None:
        if "CI" in os.environ:
            return

        # URL scheme
        from angrmanagement.logic.url_scheme import AngrUrlScheme  # pylint:disable=import-outside-toplevel

        scheme = AngrUrlScheme()
        registered, _ = scheme.is_url_scheme_registered()
        supported = scheme.is_url_scheme_supported()

        if not registered and supported and not Conf.prompted_for_url_scheme_registration:
            btn = QMessageBox.question(
                None,
                "Setting up angr URL scheme",
                'angr URL scheme allows "deep linking" from browsers and other applications '
                "by registering the angr:// protocol to the current user. Do you want to "
                "register it? You may unregister at any "
                "time in Preferences.",
                defaultButton=QMessageBox.StandardButton.Yes,
            )
            if btn == QMessageBox.StandardButton.Yes:
                try:
                    AngrUrlScheme().register_url_scheme()
                except (ValueError, FileNotFoundError) as ex:
                    QMessageBox.warning(
                        None,
                        "Error in registering angr URL scheme",
                        "Failed to register the angr URL scheme.\nThe following exception occurred:\n" + str(ex),
                    )
                    return

            Conf.prompted_for_url_scheme_registration = True
            save_config()

    #
    # Commands
    #

    def _register_commands(self) -> None:
        """
        Register basic window commands.
        """
        self.workspace.command_manager.register_commands(
            [
                BasicCommand(action.__name__, caption, action)
                for caption, action in [
                    ("Analyze: Decompile", self.decompile_current_function),
                    ("Analyze: Interact", self.interact),
                    ("Analyze: Run Analysis...", self.run_analysis),
                    ("File: Exit", self.quit),
                    ("File: Load a new binary...", self.open_file_button),
                    ("File: Load a new docker target...", self.open_docker_button),
                    ("File: Load a new trace...", self.load_trace),
                    ("File: Load angr database...", self.load_database),
                    ("File: Preferences...", self.preferences),
                    ("File: Save angr database as...", self.save_database_as),
                    ("File: Save angr database...", self.save_database),
                    ("File: Save patched binary as...", self.save_patched_binary_as),
                    ("Help: About", self.open_about_dialog),
                    ("Help: Documentation", self.open_doc_link),
                    ("View: Breakpoints", self.workspace.show_breakpoints_view),
                    ("View: Call Explorer", self.workspace.show_call_explorer_view),
                    ("View: Console", self.workspace.show_console_view),
                    ("View: Disassembly (Graph)", self.workspace.show_graph_disassembly_view),
                    ("View: Disassembly (Linear)", self.workspace.show_linear_disassembly_view),
                    ("View: Functions", self.workspace.show_functions_view),
                    ("View: Hex", self.workspace.show_hex_view),
                    ("View: Interaction", self.workspace.show_interaction_view),
                    ("View: Log", self.workspace.show_log_view),
                    ("View: New Disassembly (Graph)", self.workspace.create_and_show_graph_disassembly_view),
                    ("View: New Disassembly (Linear)", self.workspace.create_and_show_linear_disassembly_view),
                    ("View: New Hex", self.workspace.create_and_show_hex_view),
                    ("View: Patches", self.workspace.show_patches_view),
                    ("View: Proximity", self.workspace.view_proximity_for_current_function),
                    ("View: Pseudocode", self.workspace.show_pseudocode_view),
                    ("View: Registers", self.workspace.show_registers_view),
                    ("View: Stack", self.workspace.show_stack_view),
                    ("View: States", self.workspace.show_states_view),
                    ("View: Strings", self.workspace.show_strings_view),
                    ("View: Symbolic Execution", self.workspace.show_symexec_view),
                    ("View: Trace map", self.workspace.show_trace_map_view),
                    ("View: Traces", self.workspace.show_traces_view),
                    ("View: Types", self.workspace.show_types_view),
                ]
            ]
        )

    #
    # Event
    #

    def closeEvent(self, event) -> None:
        # Ask if the user wants to save things
        if (
            self.workspace.main_instance is not None
            and not self.workspace.main_instance.project.am_none
            and self.shown_at_start
        ):
            msgbox = QMessageBox()
            msgbox.setWindowTitle("Save database")
            msgbox.setText("angr management is about to exit. Do you want to save the database?")
            msgbox.setIcon(QMessageBox.Icon.Question)
            msgbox.setWindowIcon(self.windowIcon())
            msgbox.setStandardButtons(
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
            )
            msgbox.setDefaultButton(QMessageBox.StandardButton.Yes)
            r = msgbox.exec_()

            if r == QMessageBox.StandardButton.Cancel:
                event.ignore()
                return
            elif r == QMessageBox.StandardButton.Yes:
                save_r = self.save_database()
                if not save_r:
                    # failed to save the database
                    event.ignore()
                    return

        for plugin in list(self.workspace.plugins.active_plugins.values()):
            self.workspace.plugins.deactivate_plugin(plugin)
        event.accept()

    def event(self, event):
        if event.type() == QEvent.User and isinstance(event, ExecuteCodeEvent):
            try:
                event.result = event.execute()
            except Exception as ex:  # pylint:disable=broad-except
                event.exception = ex
                if event.async_:
                    _l.exception("Exception occurred in an async job:")
            event.event.set()

            return True

        return super().event(event)

    def on_screen_changed(self, screen) -> None:
        """
        When changing from one screen to another, ask disassembly views to refresh in case the DPI is changed.
        """
        self.workspace.current_screen.am_obj = screen
        self.workspace.current_screen.am_event()

    #
    # Actions
    #

    def reload(self) -> None:
        self.workspace.reload()

    def open_file_button(self) -> None:
        file_path = self.open_mainfile_dialog()
        if not file_path:
            return
        self.load_file(file_path)

    def open_trace_file_button(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open a trace file",
            Conf.last_used_directory,
            "All files (*);;Trace files (*.trace);;",
        )
        Conf.last_used_directory = os.path.dirname(file_path)
        if not file_path:
            return
        self.load_trace_file(file_path)

    def open_docker_button(self) -> None:
        required = {
            "archr: git clone https://github.com/angr/archr && cd archr && pip install -e .": archr,
            "keystone: pip install --no-binary keystone-engine keystone-engine": keystone,
        }
        is_missing = [key for key, value in required.items() if value is None]
        if len(is_missing) > 0:
            req_msg = "You need to install the following:\n\n\t" + "\n\t".join(is_missing)
            req_msg += "\n\nInstall them to enable this functionality."
            req_msg += "\nRelaunch angr-management after install."
            QMessageBox(self).critical(None, "Dependency error", req_msg)
            return

        img_name = self._pick_image_dialog()
        if img_name is None:
            return
        target = archr.targets.DockerImageTarget(img_name, target_path=None)
        self.workspace.job_manager.add_job(LoadTargetJob(self.workspace.main_instance, target))
        self.workspace.main_instance.img_name = img_name

    def load_trace_file(self, file_path) -> None:
        if isurl(file_path):
            QMessageBox.critical(
                self,
                "Unsupported Action",
                "Downloading trace files is not yet supported. Please specify a path to a file on disk.",
            )
        else:
            # File
            if os.path.isfile(file_path):
                try:
                    with open(file_path, "rb") as f:
                        loaded_sim_state = pickle.load(f)
                        analysis_params = {
                            "end_state": loaded_sim_state,
                            "start_addr": None,
                            "end_addr": None,
                            "block_addrs": None,
                        }
                        self.workspace.view_data_dependency_graph(analysis_params)
                    self._recent_file(file_path)
                except pickle.PickleError:
                    QMessageBox.critical(
                        self, "Unable to load trace file", "Trace file must contain a serialized SimState."
                    )
            else:
                QMessageBox.critical(
                    self,
                    "File not found",
                    f"angr management cannot open file {file_path}. Please make sure that the file exists.",
                )

    def load_file(self, file_path) -> None:
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
                    self.workspace.job_manager.add_job(LoadBinaryJob(self.workspace.main_instance, file_path))
            else:
                QMessageBox.critical(
                    self,
                    "File not found",
                    f"angr management cannot open file {file_path}. Please make sure that the file exists.",
                )
        else:
            # url
            r = QMessageBox.question(
                self,
                "Downloading a file",
                f"Do you want to download a file from {file_path} and open it in angr management?",
                defaultButton=QMessageBox.StandardButton.Yes,
            )
            if r == QMessageBox.StandardButton.Yes:
                try:
                    target_path = download_url(file_path, parent=self, to_file=True, file_path=None)
                except InvalidURLError:
                    QMessageBox.critical(
                        self, "Downloading failed", "angr management failed to download the file. The URL is invalid."
                    )
                    return
                except UnexpectedStatusCodeError as ex:
                    QMessageBox.critical(
                        self,
                        "Downloading failed",
                        "angr management failed to retrieve the header of the file. "
                        f"The HTTP request returned an unexpected status code {ex.status_code}.",
                    )
                    return

                if target_path:
                    # open the file - now it's a local file
                    self.workspace.main_instance.binary_path = target_path
                    self.workspace.main_instance.original_binary_path = file_path
                    self.load_file(target_path)

    def load_database(self) -> None:
        # Open File window
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load angr database",
            ".",
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
            self,
            "Save angr database",
            default_database_path,
            "angr databases (*.adb)",
        )

        if not file_path:
            return False

        if not file_path.endswith(".adb"):
            file_path = file_path + ".adb"

        return self._save_database(file_path)

    def save_patched_binary_as(self) -> None:
        if self.workspace.main_instance is None or self.workspace.main_instance.project.am_none:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save patched binary as...",
            self.workspace.main_instance.project.loader.main_object.binary
            + ".patched",  # FIXME: this will not work if we are loading from an angrdb
            "Any file (*)",
        )

        if file_path:
            b = self.workspace.main_instance.project.kb.patches.apply_patches_to_binary()
            with open(file_path, "wb") as f:
                f.write(b)

    def load_trace(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Load trace", ".", "bintrace (*.trace)")
        if not file_path:
            return
        self.workspace.load_trace_from_path(file_path)

    def preferences(self) -> None:
        pref = Preferences(self.workspace, parent=self)
        pref.exec_()

    def quit(self) -> None:
        self.close()

    def run_variable_recovery(self) -> None:
        self.workspace._get_or_create_view("disassembly", DisassemblyView).variable_recovery_flavor = "accurate"

    def run_induction_variable_analysis(self) -> None:
        self.workspace._get_or_create_view("disassembly", DisassemblyView).run_induction_variable_analysis()

    def run_dependency_analysis(self, func_addr: int | None = None, func_arg_idx: int | None = None) -> None:
        if self.workspace is None or self.workspace.main_instance is None:
            return
        dep_analysis_job = DependencyAnalysisJob(
            self.workspace.main_instance, func_addr=func_addr, func_arg_idx=func_arg_idx
        )
        self.workspace.job_manager.add_job(dep_analysis_job)

    def run_analysis(self) -> None:
        if self.workspace:
            self.workspace.run_analysis()

    def decompile_current_function(self) -> None:
        if self.workspace is not None:
            self.workspace.decompile_current_function()

    def view_proximity_for_current_function(self) -> None:
        if self.workspace is not None:
            self.workspace.view_proximity_for_current_function()

    def interact(self) -> None:
        self.workspace.interact_program(self.workspace.main_instance.img_name)

    def show_command_palette(self, parent=None) -> None:
        dlg = CommandPaletteDialog(self.workspace, parent=(parent or self))
        dlg.setModal(True)
        dlg.exec_()
        if dlg.selected_item:
            dlg.selected_item.run()

    def show_goto_palette(self, parent=None) -> None:
        dlg = GotoPaletteDialog(self.workspace, parent=(parent or self))
        dlg.setModal(True)
        dlg.exec_()
        if dlg.selected_item:
            self.workspace.jump_to(dlg.selected_item.addr)

    #
    # Other public methods
    #

    def bring_to_front(self) -> None:
        self.setWindowState((self.windowState() & ~Qt.WindowState.WindowMinimized) | Qt.WindowState.WindowActive)
        self.activateWindow()
        self.raise_()

    #
    # Private methods
    #

    def _recent_file(self, file_path) -> None:
        file_path = os.path.abspath(file_path)
        self._file_menu.add_recent(file_path)
        Conf.recent_file(file_path)
        save_config()

    def _get_recent_dir(self) -> str:
        if Conf.recent_files:
            recent_dir = os.path.dirname(Conf.recent_files[-1])
            if os.path.isdir(recent_dir):
                return recent_dir
        return ""

    def _load_database(self, file_path: str) -> None:
        other_kbs = {}
        extra_info = {}

        job = LoadAngrDBJob(
            self.workspace.main_instance,
            file_path,
            ["global", "pseudocode_variable_kb"],
            other_kbs=other_kbs,
            extra_info=extra_info,
        )
        # TODO: make the job return what the callback wants
        job._on_finish = partial(self._on_load_database_finished, job)
        self.workspace.job_manager.add_job(job)

    def _on_load_database_finished(self, job: LoadAngrDBJob, *args, **kwargs) -> None:  # pylint:disable=unused-argument
        proj = job.project

        if proj is None:
            return

        self._recent_file(job.file_path)

        cfg = proj.kb.cfgs["CFGFast"]
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
        self.workspace.on_cfg_generated((cfg, cfb))
        self.workspace.plugins.angrdb_load_entries(job.extra_info)

    def _save_database(self, file_path) -> bool:
        if self.workspace.main_instance is None or self.workspace.main_instance.project.am_none:
            return False

        self.workspace.plugins.handle_project_save(file_path)

        angrdb = AngrDB(project=self.workspace.main_instance.project)
        extra_info = self.workspace.plugins.angrdb_store_entries()
        angrdb.dump(
            file_path,
            kbs=[
                self.workspace.main_instance.kb,
                self.workspace.main_instance.pseudocode_variable_kb,
            ],
            extra_info=extra_info,
        )

        self.workspace.main_instance.database_path = file_path
        return True

    def _raise_view(self, idx: int) -> None:
        """
        Raise idx'th view in the dock manager
        """
        try:
            dock = self.dock_manager.dockWidgets()[idx]
        except IndexError:
            return
        dock.raise_()
