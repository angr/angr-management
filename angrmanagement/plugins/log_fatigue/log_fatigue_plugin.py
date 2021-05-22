import asyncio

from PySide2.QtCore import QEvent

from slacrs import Slacrs
from slacrs.model import HumanFatigue
from tornado.platform.asyncio import AnyThreadEventLoopPolicy

from ..base_plugin import BasePlugin


class LogFatiguePlugin(BasePlugin):
    def __init__(self, workspace):
        super().__init__(workspace)
        self._fatigue = HumanFatigue()
        self._strokes = []
        self.log_fatigue()
        self._main_window = workspace.view_manager.main_window
        self._main_window.setMouseTracking(True)
        self._main_window.eventFilter = self.eventFilter
        self._main_window.installEventFilter(self._main_window)

    def log_fatigue(self):
        import threading

        t_log = threading.Thread(target=self._log_mouse, args=())
        t_log.start()

    def _log_mouse(self):
        from time import sleep

        asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())
        self.slacr = Slacrs()
        self.session = self.slacr.session()
        while self._main_window._fatigue_flag is True:
            sleep(2)
            if self._main_window.username:
                self._fatigue.user = self._main_window.username
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
