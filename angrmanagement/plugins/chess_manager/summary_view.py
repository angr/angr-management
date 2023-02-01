# pylint:disable=missing-class-docstring
import datetime
import json
import threading
from time import sleep
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)
from sqlalchemy import func as sqlalchemy_func

from angrmanagement.logic.threads import gui_thread_schedule_async
from angrmanagement.ui.views.view import BaseView

try:
    from slacrs import Slacrs
    from slacrs.model import PluginMessage
except ImportError:
    Slacrs = None

if TYPE_CHECKING:
    from .chess_connector import ChessConnector


#
# Plugin Log
#


class QPluginItem:
    def __init__(self, plugin, kind, image_id, msg):
        self.plugin = plugin
        self.kind = kind
        self.image_id = image_id
        self.msg = msg

    def widgets(self):
        widgets = [
            QTableWidgetItem(self.plugin),
            QTableWidgetItem(self.kind),
            QTableWidgetItem(self.image_id),
            QTableWidgetItem(self.msg),
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QPluginsLogTable(QTableWidget):
    HEADER = [
        "Plugin",
        "Kind",
        "Image ID",
        "Message",
    ]

    def __init__(self, workspace, parent=None):
        super().__init__(parent)
        self.workspace = workspace

        self.setColumnCount(len(self.HEADER))
        self.setHorizontalHeaderLabels(self.HEADER)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)

        self.items = []
        self.cnt = 0

    def reload(self):
        self.setRowCount(len(self.items))

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

        self.viewport().update()

    def update_table(self, messages):
        self.items = []

        for msg in messages:
            self.items.append(QPluginItem(msg.plugin, msg.kind, msg.target_image_id, msg.message))

        self.reload()


#
#
#


class QFuzztainerItem:
    def __init__(self, data):
        self.data = data

    def widgets(self):
        widgets = [
            QTableWidgetItem(self.data),
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QFuzztainerTable(QTableWidget):
    DISPLAY_ORDER = [
        "execs_per_sec",
        "unique_crashes",
        "unique_hangs",
        "paths_found",
        "paths_total",
        "testcache_size",
        "testcache_count",
        "testcache_evict",
        "run_time",
        "cycles_done",
        "cycles_wo_finds",
        "execs_done",
        "paths_favored",
        "max_depth",
        "pending_favs",
        "pending_total",
        "variable_paths",
        "execs_since_crash",
        "slowest_exec_ms",
        "edges_found",
    ]

    HEADER = [
        "execs/sec",
        "unique crashes",
        "unique hangs",
        "paths found",
        "paths total",
        "testcache size",
        "testcache count",
        "testcache evict",
        "run time",
        "cycles done",
        "cycles w/o finds",
        "execs done",
        "paths favored",
        "max depth",
        "pending favs",
        "pending total",
        "variable paths",
        "execs since crash",
        "slowest exec ms",
        "edges found",
    ]

    def __init__(self, workspace, idx, parent=None):
        super().__init__(parent)
        self.workspace = workspace
        self.idx = idx

        self.setRowCount(len(self.HEADER[self.idx * 10 : self.idx * 10 + 10]))
        self.setVerticalHeaderLabels(self.HEADER[self.idx * 10 : self.idx * 10 + 10])
        self.setColumnCount(1)

        self.verticalHeader().setVisible(True)
        self.horizontalHeader().setVisible(False)

        self.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)

        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)

        self.items = []

    def reload(self):
        self.setRowCount(len(self.items))

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

        self.viewport().update()

    def update_table(self, messages):
        if messages is None:
            return

        self.items = []

        messages = messages[::-1]
        for msg in messages:
            if msg.plugin.lower() == "fuzztainer" and msg.kind == "info":
                try:
                    stats = json.loads(msg.message)
                except Exception as ex:  # pylint:disable=broad-except
                    print(ex)
                    continue

                try:
                    stats["execs_per_sec"]
                except KeyError as e:
                    print(e)
                    continue

                for stat_name in self.DISPLAY_ORDER[self.idx * 10 : self.idx * 10 + 10]:
                    stat_data = stats[stat_name]
                    self.items.append(QFuzztainerItem(stat_data))

                break

        self.reload()


class SummaryView(BaseView):
    def __init__(self, workspace, default_docking_position, connector: "ChessConnector", *args, **kwargs):
        super().__init__("chess_summary", workspace, default_docking_position, *args, **kwargs)
        self.base_caption = "CHESS"

        self.workspace = workspace
        self.connector = connector

        self._init_widgets()

        # start the worker routine
        self.should_work = Slacrs is not None
        self.worker_thread = threading.Thread(target=self.worker_routine)
        self.worker_thread.setDaemon(True)
        self.worker_thread.start()

    def teardown(self):
        self.should_work = False
        self.close()

    #
    # UI
    #

    def _init_widgets(self):
        self.fuzztainer_table_1 = QFuzztainerTable(self.workspace, 0)
        self.fuzztainer_table_2 = QFuzztainerTable(self.workspace, 1)
        self.log_table = QPluginsLogTable(self.workspace)

        #
        # fuzztainer tab
        #

        self.fuzztainer_tab = QWidget()
        fuzz_layout = QHBoxLayout()
        fuzz_layout.addWidget(self.fuzztainer_table_1)
        fuzz_layout.addWidget(self.fuzztainer_table_2)
        self.fuzztainer_tab.setLayout(fuzz_layout)

        #
        # plugin log tab
        #

        self.log_tab = QWidget()
        log_layout = QHBoxLayout()
        log_layout.addWidget(self.log_table)
        self.log_tab.setLayout(log_layout)

        #
        # final tab setup
        #

        # tabs for multiple summaries
        self.tabView = QTabWidget()
        self.tabView.addTab(self.fuzztainer_tab, "Fuzztainer")
        self.tabView.addTab(self.log_tab, "Plugins Log")

        layout = QVBoxLayout()
        layout.addWidget(self.tabView)

        #
        # status bar
        #
        self.status_bar = QLabel()

        layout.addWidget(self.status_bar)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)
        self.show()

    def set_status(self, text: str):
        self.status_bar.setText(text)

    #
    # Data Threading
    #

    def worker_routine(self):
        while self.should_work:
            if self.connector is None or not self.connector.connected:
                gui_thread_schedule_async(self.set_status, args=("Not connected to CHECRS backend.",))
                sleep(10)
                continue

            if not self.connector.target_image_id:
                gui_thread_schedule_async(self.set_status, args=("No associated remote target.",))
                sleep(2)
                continue

            sleep(5)

            gui_thread_schedule_async(self.set_status, args=("Refreshing...",))
            session = None
            try:
                session = self._init_session()

                if not session:
                    continue

                self._update_tables(session, self.connector.target_image_id)
            finally:
                if session is not None:
                    session.close()

            last_updated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            gui_thread_schedule_async(self.set_status, args=(f"Ready. Last updated at {last_updated}.",))

    def _init_session(self):
        if self.connector is None:
            self.connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")
            if self.connector is None:
                return None

        try:
            slacrs_instance = self.connector.slacrs_instance()
        except Exception:
            return None

        if slacrs_instance is None:
            return None

        session = slacrs_instance.session()
        return session

    @staticmethod
    def _find_latest_fuzztainer_stats(messages):
        messages = messages[::-1]
        for msg in messages:
            if msg.plugin.lower() == "fuzztainer" and msg.kind == "info":
                try:
                    stats = json.loads(msg.message)
                except Exception as e:
                    print(e)
                    continue

                try:
                    stats["execs_per_sec"]
                except KeyError as e:
                    print(e)
                    continue

                return [msg]
        return None

    def _update_tables(self, session, target_image_id: str):
        res = (
            session.query(PluginMessage)
            .filter(
                sqlalchemy_func.lower(PluginMessage.plugin) == "fuzztainer",
                PluginMessage.kind == "info",
                PluginMessage.target_image_id == target_image_id,
            )
            .order_by(PluginMessage.created_at.desc())
            .limit(50)
        )
        if not res:
            return

        messages = res.all()
        if not messages:
            return

        fuzztainer_msgs = self._find_latest_fuzztainer_stats(messages)
        self.log_table.update_table(messages)
        self.fuzztainer_table_1.update_table(fuzztainer_msgs)
        self.fuzztainer_table_2.update_table(fuzztainer_msgs)
