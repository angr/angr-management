"""
Jobs, signals and the UI executor work without Qt.
"""

# pylint: disable=protected-access,no-self-use

from __future__ import annotations

import logging
import os
import threading
import unittest
from typing import TYPE_CHECKING

from headless import run_without_qt, test_location  # pylint: disable=import-error

from angrmanagement.data.load_options import _confirm_symbol_download
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.signal import Signal
from angrmanagement.logic.threads import DirectExecutor, gui_thread_schedule, gui_thread_schedule_async, is_gui_thread
from angrmanagement.logic.ui_services import HeadlessServices

if TYPE_CHECKING:
    from collections.abc import Sequence

FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")

CFG_JOB_SCRIPT = """
import threading

import angr

from angrmanagement.data.instance import Instance
from angrmanagement.data.jobs import CFGGenerationJob
from angrmanagement.data.jobs.job import JobState
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.jobmanager import JobManager
from angrmanagement.logic.threads import DirectExecutor

instance = Instance()
instance.project.am_obj = angr.Project(BINARY, auto_load_libs=False)
instance.project.am_event()

job_manager = JobManager(None)
events = []
job_manager.job_starting.connect(lambda job: events.append(("starting", threading.current_thread().name)))
job_manager.job_finished.connect(lambda job: events.append(("finished", threading.current_thread().name)))
finished = {}


def on_finish(result):
    cfg_model, cfb = result
    finished["thread"] = threading.current_thread().name
    functions = instance.project.kb.functions
    finished["functions"] = len(functions)
    finished["has_main"] = functions.function(name="main") is not None
    finished["model"] = type(cfg_model).__name__
    finished["cfb"] = type(cfb).__name__


job = CFGGenerationJob(instance, on_finish=on_finish)
job_manager.add_job(job)
job_manager.join_all_jobs()
job_manager.quit()

RESULT = {
    "executor": type(GlobalInfo.executor).__name__,
    "main_thread": threading.main_thread().name,
    "finished": finished,
    "events": events,
    "state": job.state.name,
    "jobs_left": len(job_manager.jobs),
    "worker_alive": job_manager._worker_thread.is_alive(),
}
"""


class TestHeadlessCFGJob(unittest.TestCase):
    """Run a CFG recovery through the job manager in an interpreter without PySide6."""

    def test_cfg_generation_job_on_fauxware(self):
        outcome = run_without_qt(f"BINARY = {FAUXWARE!r}\n" + CFG_JOB_SCRIPT)
        result = outcome["result"]

        assert outcome["qt_modules_loaded"] == []
        assert result["executor"] == "DirectExecutor"
        assert result["state"] == "FINISHED"
        assert result["jobs_left"] == 0
        assert result["worker_alive"] is False
        # the finish handler and the signals ran on the thread that pumped the executor, not on the worker
        assert result["finished"]["thread"] == result["main_thread"]
        assert result["finished"]["has_main"] is True
        assert result["finished"]["functions"] > 10
        assert result["finished"]["cfb"] == "CFBlanket"
        assert result["finished"]["model"] == "CFGModel"
        assert [tuple(event) for event in result["events"]] == [
            ("starting", result["main_thread"]),
            ("finished", result["main_thread"]),
        ]


class DirectExecutorTestCase(unittest.TestCase):
    """Installs a DirectExecutor owned by the test's thread for the duration of a test."""

    def setUp(self) -> None:
        self._saved_executor = GlobalInfo._executor
        self.executor = DirectExecutor()
        GlobalInfo.executor = self.executor

    def tearDown(self) -> None:
        GlobalInfo.executor = self._saved_executor

    def run_in_thread(self, func) -> threading.Thread:
        thread = threading.Thread(target=func, daemon=True)
        thread.start()
        return thread


class TestSignal(DirectExecutorTestCase):
    """Signal delivers on the UI thread, like a Qt auto connection to an object on the GUI thread."""

    def test_emit_on_the_ui_thread_is_inline(self):
        signal = Signal(int)
        got = []
        signal.connect(got.append)
        signal.emit(1)
        assert got == [1]

    def test_emit_from_another_thread_waits_for_the_pump(self):
        signal = Signal(int, str)
        got = []
        signal.connect(lambda number, text: got.append((number, text, threading.current_thread())))

        self.run_in_thread(lambda: signal.emit(7, "seven")).join()
        assert not got

        assert self.executor.process_pending() == 1
        assert got == [(7, "seven", threading.current_thread())]

    def test_listeners_taking_fewer_arguments_get_the_leading_ones(self):
        signal = Signal(object, object)
        got = []
        signal.connect(got.append)
        signal.connect(lambda: got.append("no arguments"))
        signal.emit("job", "exception")
        assert got == ["job", "no arguments"]

    def test_a_qt_connection_type_is_accepted_and_ignored(self):
        # code written for Qt signals may pass one, e.g. Qt.ConnectionType.QueuedConnection
        signal = Signal(int)
        got = []
        signal.connect(got.append, object())
        signal.emit(1)
        assert got == [1]

        self.run_in_thread(lambda: signal.emit(2)).join()
        assert got == [1]
        assert self.executor.process_pending() == 1
        assert got == [1, 2]

    def test_a_raising_listener_is_logged_and_the_rest_still_run(self):
        signal = Signal()
        got = []

        def bad() -> None:
            raise ValueError("listener failure")

        signal.connect(bad)
        signal.connect(lambda: got.append("ran"))
        with self.assertLogs("angrmanagement.logic.signal", level=logging.ERROR):
            signal.emit()
        assert got == ["ran"]

    def test_disconnect(self):
        signal = Signal(int)
        got = []
        signal.connect(got.append)
        signal.connect(got.append)
        assert signal.disconnect(got.append) is True
        signal.emit(1)
        assert got == [1]
        assert signal.disconnect() is True
        signal.emit(2)
        assert got == [1]
        assert signal.disconnect(got.append) is False


class TestDirectExecutor(DirectExecutorTestCase):
    """The module functions of logic/threads.py on a headless executor."""

    def test_the_creating_thread_is_the_ui_thread(self):
        assert is_gui_thread() is True
        seen = []
        self.run_in_thread(lambda: seen.append(is_gui_thread())).join()
        assert seen == [False]

    def test_schedule_from_a_thread_returns_the_result_once_pumped(self):
        box = {}

        def worker() -> None:
            box["result"] = gui_thread_schedule(lambda a, b: (a + b, threading.current_thread()), args=(2, 3))

        thread = self.run_in_thread(worker)
        assert self.executor.pump_until(lambda: not thread.is_alive(), timeout=30)
        assert box["result"] == (5, threading.current_thread())

    def test_schedule_reraises_and_times_out(self):
        box = {}
        go_on = threading.Event()

        def raising() -> None:
            raise KeyError("from the UI thread")

        def worker() -> None:
            try:
                gui_thread_schedule(raising)
            except KeyError as ex:
                box["raised"] = ex
            go_on.wait(timeout=30)
            box["timed_out"] = gui_thread_schedule(lambda: "never pumped in time", timeout=0.05)

        thread = self.run_in_thread(worker)
        # pump until the first call has run, then stop pumping so that the second one times out
        assert self.executor.pump_until(lambda: "raised" in box, timeout=30)
        go_on.set()
        thread.join(timeout=30)
        assert isinstance(box["raised"], KeyError)
        assert box["timed_out"] is None
        # like the Qt executor, a timed-out call still runs once the UI thread pumps
        assert self.executor.process_pending() == 1

    def test_schedule_async_on_the_ui_thread_runs_inline(self):
        got = []
        gui_thread_schedule_async(got.append, args=(1,))
        assert got == [1]
        self.run_in_thread(lambda: gui_thread_schedule_async(got.append, args=(2,))).join()
        assert got == [1]
        self.executor.process_pending()
        assert got == [1, 2]

    def test_symbol_download_is_confirmed_on_the_ui_thread(self):
        # cle asks from the loading thread; the question must reach the user on the UI thread
        asked = []

        class Services(HeadlessServices):
            """Answers every question with its default and records the thread it was asked on."""

            def question(self, title: str, text: str, buttons: Sequence[str], default: str) -> str:
                asked.append((title, text, tuple(buttons), threading.current_thread()))
                return default

        saved_services = GlobalInfo._ui_services
        GlobalInfo.ui_services = Services()
        try:
            box = {}
            thread = self.run_in_thread(lambda: box.setdefault("answer", _confirm_symbol_download("http://symbols")))
            assert self.executor.pump_until(lambda: not thread.is_alive(), timeout=30)
        finally:
            GlobalInfo.ui_services = saved_services
        assert box["answer"] is True
        assert asked == [
            (
                "Confirm Symbol Download",
                "Download debug symbols from:\nhttp://symbols",
                ("Yes", "No"),
                threading.current_thread(),
            )
        ]

    def test_process_pending_does_nothing_off_the_ui_thread(self):
        got = []
        self.run_in_thread(lambda: gui_thread_schedule_async(got.append, args=(1,))).join()
        counts = []
        self.run_in_thread(lambda: counts.append(self.executor.process_pending())).join()
        assert counts == [0]
        assert not got
        assert self.executor.process_pending() == 1


if __name__ == "__main__":
    unittest.main()
