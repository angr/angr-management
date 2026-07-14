from __future__ import annotations

import sys
import threading
import time
import traceback

from PySide6.QtCore import Qt, QTimer


class StallWatchdog:
    def __init__(self, app, tick_ms=20, stall_ms=100):
        self._stall = stall_ms / 1000
        self._last = time.perf_counter()
        self._main = threading.main_thread().ident
        self._running = True
        self._timer = QTimer()
        self._timer.setTimerType(Qt.TimerType.PreciseTimer)
        self._timer.timeout.connect(lambda: setattr(self, "_last", time.perf_counter()))
        self._timer.start(tick_ms)
        self._thread = threading.Thread(target=self._watch, daemon=True)
        self._thread.start()
        app.aboutToQuit.connect(lambda: setattr(self, "_running", False))

    def _watch(self):
        if self._main is None:
            return
        while self._running:
            time.sleep(0.01)
            blocked = time.perf_counter() - self._last
            if blocked > self._stall:
                frame = sys._current_frames().get(self._main)
                stack = "".join(traceback.format_stack(frame)) if frame else "?"
                print(f"[STALL] main blocked ~{blocked * 1000:.0f} ms\n{stack}", file=sys.stderr)
                while self._running and time.perf_counter() - self._last > self._stall:
                    time.sleep(0.02)  # don't spam until it recovers
