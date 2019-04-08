import pickle
import os

from PySide2.QtWidgets import QMainWindow, QTabWidget, QFileDialog, QProgressBar, QMessageBox, QSplitter, QHBoxLayout, QWidget, QShortcut
from PySide2.QtGui import QResizeEvent, QIcon, QDesktopServices, QKeySequence
from PySide2.QtCore import Qt, QSize, QEvent, QTimer, QUrl

import angr

from ..logic import GlobalInfo
from ..data.instance import Instance
from .menus.file_menu import FileMenu
from .menus.analyze_menu import AnalyzeMenu
from .menus.help_menu import HelpMenu
from .menus.view_menu import ViewMenu
from ..config import IMG_LOCATION
from .workspace import Workspace
from .dialogs.load_binary import LoadBinary, LoadBinaryError
from .dialogs.new_state import NewState
from .toolbars import StatesToolbar, AnalysisToolbar, FileToolbar
from functools import partial


class MainWindow(QMainWindow):
    """
    The main window of angr management.
    """
    def __init__(self, file_to_open=None, parent=None):
        super(MainWindow, self).__init__(parent)

        icon_location = os.path.join(IMG_LOCATION, 'angr.png')
        self.setWindowIcon(QIcon(icon_location))

        GlobalInfo.main_window = self

        # initialization
        self.caption = "angr Management"
        self.setMinimumSize(QSize(400, 400))
        self.setDockNestingEnabled(True)

        self.right_dockable_views = None
        #self._undockCurrentView = None

        self.workspace = None
        self.central_widget = None

        self._file_toolbar = None  # type: FileToolbar
        self._states_toolbar = None  # type: StatesToolbar
        self._analysis_toolbar = None  # type: AnalysisToolbar
        self._progressbar = None  # type: QProgressBar
        self._load_binary_dialog = None

        self._status = ""
        self._progress = None

        self.defaultWindowFlags = None

        self._init_toolbars()
        self._init_statusbar()
        self._init_workspace()
        self._init_shortcuts()
        self._init_menus()

        self.showMaximized()

        # I'm ready to show off!
        self.show()

        self.status = "Ready."

        if file_to_open is not None:
            # load a binary
            if file_to_open.endswith(".adb"):
                self._load_database(file_to_open)
            else:
                self._open_loadbinary_dialog(file_to_open)

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

    def _open_loadbinary_dialog(self, file_to_open):
        try:
            self._load_binary_dialog = LoadBinary(file_to_open)
            self._load_binary_dialog.setModal(True)
            self._load_binary_dialog.exec_()


            if self._load_binary_dialog.cfg_args is not None:
                # load the binary
                self._load_binary(file_to_open,
                                  load_options=self._load_binary_dialog.load_options,
                                  cfg_args=self._load_binary_dialog.cfg_args
                                  )
        except LoadBinaryError:
            pass

    def open_newstate_dialog(self):
        new_state_dialog = NewState(self.workspace.instance, parent=self)
        new_state_dialog.exec_()

    def open_doc_link(self):
        QDesktopServices.openUrl(QUrl("https://docs.angr.io/", QUrl.TolerantMode))

    def open_about_dialog(self):
        QMessageBox.about(self, "About angr", "Version 8")
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
        fileMenu = FileMenu(self)
        analyzeMenu = AnalyzeMenu(self)
        viewMenu = ViewMenu(self)
        helpMenu = HelpMenu(self)
        self.menuBar().addMenu(fileMenu.qmenu())
        self.menuBar().addMenu(analyzeMenu.qmenu())
        self.menuBar().addMenu(viewMenu.qmenu())
        self.menuBar().addMenu(helpMenu.qmenu())

    #
    # Workspace
    #

    def _tabify(self):
        print("Tabifying")
        self.right_dockable_views = [dock for dock in           self.workspace.dockable_views if dock.widget() is not None and dock.widget().default_docking_position == 'right']

        for d0, d1 in zip(self.right_dockable_views, self.right_dockable_views[1:]):
            print(d0.widget().caption)
            self.central_widget.tabifyDockWidget(d0, d1)
        self.right_dockable_views[0].raise_()
        print("TABIFIED - " + str(len(self.right_dockable_views)))


    def _init_workspace(self):
        self.central_widget_main = QSplitter(Qt.Horizontal)
        self.setCentralWidget(self.central_widget_main)
        self.central_widget = QMainWindow()
        self.central_widget2 = QMainWindow()
        self.central_widget_main.addWidget(self.central_widget)
        self.central_widget_main.addWidget(self.central_widget2)

        wk = Workspace(self, Instance())
        self.workspace = wk

        self._tabify()

        # for dock in self.workspace.dockable_views:
        #     print(dock.default_docking_position)

        #try:
        

        #except:
        #    pass



        # self.right_dockable_views2 = [dock for dock in self.workspace.dockable_views2 if dock.widget().default_docking_position == 'right']
        #                         if dock.widget().default_docking_position == 'right']

        # for d02, d12 in zip(self.right_dockable_views2, self.right_dockable_views2[1:]):
        #     self.central_widget2.tabifyDockWidget(d02, d12)
        # self.right_dockable_views2[0].raise_()
        

        #self.central_widget.splitDockWidget(right_dockable_views[3], right_dockable_views[4], Qt.Horizontal)
        self.central_widget.setTabPosition(Qt.RightDockWidgetArea, QTabWidget.North)
        # self.central_widget2.setTabPosition(Qt.RightDockWidgetArea, QTabWidget.North)


    #
    # Shortcuts and Shortcut handlers
    #

    # def _undockCurrentView(self):
    #     print("undocking current view")
    #     currentTab = self.central_widget.tabPosition(Qt.RightDockWidgetArea)
    #     print("Current view: " + str(currentTab))
    #     self.defaultWindowFlags = self.right_dockable_views[currentTab].windowFlags()
    #     self.right_dockable_views[currentTab].setWindowFlags(Qt.Window)
    #     self.right_dockable_vie.split_view
    #     self.right_dockable_vie.split_view

    # def _dockCurrentView(self):.split_view
    #     print("docking current view")
    #     currentTab = self.central_widget.tabPosition(Qt.RightDockWidgetArea)
    #     print("Current view: " + str(currentTab))
    #     self.right_dockable_views[currentTab].setWindowFlags(Qt.Widget)
    #     self.right_dockable_views[currentTab].setWindowFlags(QMainWindow.VerticalTabs)
    #     # self.central_widget.tabifyDockWidget(self.right_dockable_views[0], self.right_dockable_views[1])
    #     self.right_dockable_views[currentTab].show()
    #     self.right_dockable_views[currentTab].raise_()


    def getCurrentTabId(self):
        print("Getting current tab ID\n")
        for i in range(1,6):
            if self.right_dockable_views[i-1].visibleRegion().isEmpty() == False:
                print(i)
                return i
        print("1")
        return 1


    def nextTab(self):
        self.right_dockable_views[self.getCurrentTabId()].raise_()

    def previousTab(self):
        self.right_dockable_views[self.getCurrentTabId()-2].raise_()

    def _init_shortcuts(self):

        #for i in range(1,6):
        #QShortcut(QKeySequence('Ctrl+L'), self, self.getCurrentTabId)
        QShortcut(QKeySequence('Ctrl+D'), self, self.workspace.split_view)
        QShortcut(QKeySequence('Ctrl+U'), self, self.workspace.unsplit_view)
        QShortcut(QKeySequence('Ctrl+Tab'), self, self.nextTab)
        QShortcut(QKeySequence('Ctrl+Shift+Tab'), self, self.previousTab)

        for i in range(1,len(self.right_dockable_views)):
            QShortcut(QKeySequence('Ctrl+'+str(i)), self, self.right_dockable_views[i-1].raise_)

    #
    # Event
    #

    def resizeEvent(self, event):
        """

        :param QResizeEvent event:
        :return:
        """

        pass
        # self._recalculate_view_sizes(event.oldSize())

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

    def load_binary(self):

        # Open File window
        file_path, _ = QFileDialog.getOpenFileName(self, "Open a binary", ".",
                                                   "All executables (*);;Windows PE files (*.exe);;Core Dumps (*.core);;angr database (*.adb)",
                                                   )

        if os.path.isfile(file_path):
            if file_path.endswith(".adb"):
                self._load_database(file_path)
            else:
                self._open_loadbinary_dialog(file_path)

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
        self.workspace.views_by_category['disassembly'][0].variable_recovery_flavor = 'accurate'

    def run_induction_variable_analysis(self):
        self.workspace.views_by_category['disassembly'][0].run_induction_variable_analysis()

    def decompile_current_function(self):
        if self.workspace is not None:
            self.workspace.decompile_current_function()

    #
    # Other public methods
    #

    def progress_done(self):
        self._progress = None
        self._progressbar.hide()

    #
    # Private methods
    #

    def _load_binary(self, file_path, load_options=None, cfg_args=None):
        if load_options is None:
            load_options = {}

        if cfg_args is None:
            cfg_args = {}

        proj = angr.Project(file_path, load_options=load_options)
        self.workspace.instance.set_project(proj)
        self.workspace.instance.initialize(cfg_args=cfg_args)

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
        adjustable_dockable_views = [dock for dock in self.workspace.dockable_views
                                     if dock.widget().default_docking_position in ('left', 'bottom', 'right')]

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
                    ratio = dock.old_size.width() * 1.0 / old_size.width()
                    new_width = int(self.width() * ratio)
                    self._resize_dock_widget(dock, new_width, widget.height())
                elif widget.default_docking_position == 'bottom':
                    # we want to adjust the height
                    ratio = dock.old_size.height() * 1.0 / old_size.height()
                    new_height = int(self.height() * ratio)
                    self._resize_dock_widget(dock, widget.width(), new_height)

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
