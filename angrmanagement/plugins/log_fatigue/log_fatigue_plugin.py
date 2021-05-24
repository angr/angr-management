import asyncio

from PySide2.QtCore import QEvent
from PySide2.QtWidgets import QDialog, QLabel, QLineEdit, QPushButton, QVBoxLayout

from slacrs import Slacrs
from slacrs.model import HumanFatigue
from tornado.platform.asyncio import AnyThreadEventLoopPolicy

from ..base_plugin import BasePlugin

#
# Plugin to capture the User Mouse Movements.
# User must input their name to use this plugin.
#


class LogFatiguePlugin(BasePlugin):
    def __init__(self, workspace):
        self.username = None
        self._fatigue_flag = True
        super().__init__(workspace)
        self._fatigue = HumanFatigue()
        self._strokes = []
        self.log_fatigue()
        self._main_window = workspace.view_manager.main_window
        self._main_window.setMouseTracking(True)
        self._main_window.eventFilter = self.eventFilter
        self._main_window.installEventFilter(self._main_window)
        self.modal = self.Modal(self)
        self.modal.show()

    def log_fatigue(self):
        import threading

        t_log = threading.Thread(target=self._log_mouse, args=())
        t_log.start()

    def _log_mouse(self):
        from time import sleep

        asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())
        self.slacr = Slacrs()
        self.session = self.slacr.session()
        while self._fatigue_flag is True:
            sleep(2)
            if self._fatigue.user:
                self.session.add(self._fatigue)
                self.session.commit()

    def eventFilter(self, obj, event):
        if event.type() == QEvent.HoverMove:
            x = event.pos().x()
            old_x = event.oldPos().x()
            y = event.pos().y()
            old_y = event.oldPos().y()
            import math

            self._fatigue.mouse_speed = int(
                math.sqrt((x - old_x) ** 2 + (y - old_y) ** 2)
            )
        elif event.type() == QEvent.KeyPress:
            import time

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
            self.username = None

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
            if not self.outerclass.username:
                self.outerclass._fatigue_flag = False
                self.outerclass.workspace.plugins.deactivate_plugin(self.outerclass)

    def teardown(self):
        self._fatigue_flag = False
        self.modal.close()
