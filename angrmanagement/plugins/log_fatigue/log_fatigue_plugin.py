import asyncio
import math
import threading
import time
from time import sleep
from typing import Optional

from PySide6.QtCore import QEvent, QObject
from PySide6.QtWidgets import QDialog, QLabel, QLineEdit, QPushButton, QVBoxLayout

from angrmanagement.plugins.base_plugin import BasePlugin

try:
    from slacrs import Slacrs
    from slacrs.model import HumanFatigue
except ImportError:
    Slacrs: Optional[type] = None
    HumanFatigue: Optional[type] = None
from tornado.platform.asyncio import AnyThreadEventLoopPolicy

#
# Plugin to capture the User Mouse Movements.
# User must input their name to use this plugin.
#


class LogFatiguePlugin(BasePlugin):
    def __init__(self, workspace):
        if not Slacrs:
            raise Exception("Please install Slacrs to Initialize LogFatigue Plugin")
        self._fatigue_flag = True
        super().__init__(workspace)
        self._fatigue = HumanFatigue()
        self._strokes = []
        self._main_window = workspace.view_manager.main_window
        self._main_window.setMouseTracking(True)
        self.EventFilterInstance = self.EventFilter(self._fatigue)
        self._main_window.installEventFilter(self.EventFilterInstance)
        self.modal = self.Modal(self)
        self.modal.show()

        self.t_log = threading.Thread(target=self._log_mouse, args=())
        self.t_log.setDaemon(True)
        self.t_log.start()

    def _log_mouse(self):
        asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())

        connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")
        if connector is None:
            # chess connector does not exist
            return None
        slacrs_instance = connector.slacrs_instance()
        if slacrs_instance is None:
            # slacrs does not exist. continue
            return None
        session = slacrs_instance.session()
        with session.no_autoflush:
            while self._fatigue_flag is True:
                sleep(2)
                if self._fatigue.user:
                    session.add(self._fatigue)
                    session.commit()
            session.close()

    class EventFilter(QObject):
        def __init__(self, fatigue):
            super().__init__()
            self._fatigue = fatigue
            self._strokes = []

        def eventFilter(self, obj, event):  # pylint: disable=unused-argument
            if event.type() == QEvent.HoverMove:
                x = event.pos().x()
                old_x = event.oldPos().x()
                y = event.pos().y()
                old_y = event.oldPos().y()

                self._fatigue.mouse_speed = int(math.sqrt((x - old_x) ** 2 + (y - old_y) ** 2))
            elif event.type() == QEvent.KeyPress:
                timestamp = time.time()
                i = 0
                for i in range(len(self._strokes)):
                    if timestamp - self._strokes[i] <= 10:
                        break
                self._strokes = self._strokes[i:]
                self._strokes.append(timestamp)
                self._fatigue.stroke = len(self._strokes)

            return False

    #
    # Creates Model so user can input name, if modal is closed without submitting name,
    # the LogFatigue plugin will be deactivated
    #

    class Modal(QDialog):
        def __init__(self, outerclass):
            super().__init__(outerclass._main_window)

            self.label = QLabel("Enter your Name")
            self.edit = QLineEdit("")
            self.button = QPushButton("Submit")
            self.outerclass = outerclass

            layout = QVBoxLayout()

            layout.addWidget(self.label)
            layout.addWidget(self.edit)
            layout.addWidget(self.button)

            self.setLayout(layout)

            self.button.clicked.connect(self.input)

        def input(self):
            self.outerclass._fatigue.user = self.edit.text()
            self.close()

        def closeEvent(self, event):
            if not self.outerclass._fatigue.user:
                self.outerclass._fatigue_flag = False
                self.outerclass.workspace.plugins.deactivate_plugin(self.outerclass)
            event.accept()

    def teardown(self):
        self._fatigue_flag = False
        self.t_log.join()
