from __future__ import annotations

# Preload fastmcp (and therefore pydantic) before any test module imports PySide6. PySide6's
# shiboken __feature__ import hook otherwise collides with pydantic's lazy imports under pytest,
# breaking fastmcp import and causing test_mcp_server to skip depending on collection order.
import atexit
import contextlib
import os
import shutil
import tempfile

with contextlib.suppress(ImportError):
    import fastmcp  # noqa: F401  # pylint:disable=unused-import


import sys
import threading
from functools import partial

import pytest
from stack_dump import DIRECTORY_VARIABLE, LateStackDump, left_behind  # pylint: disable=import-error

# Keep the tests' configuration away from the user's: angr management reads and saves config.toml in this directory.
# It is set at import, before any test module imports angrmanagement.config, and removed when the process that made
# it exits. Every xdist worker makes its own, whatever it inherits from the controller: workers that shared one file
# read each other's saves, and a test that saves and reads back the configuration found another worker's file.
_xdist_worker = os.environ.get("PYTEST_XDIST_WORKER")
if _xdist_worker or not os.environ.get("ANGR_MANAGEMENT_CONFIG_DIR"):
    _config_dir = tempfile.mkdtemp(
        prefix=f"angr-management-test-config-{_xdist_worker}-" if _xdist_worker else "angr-management-test-config-"
    )
    os.environ["ANGR_MANAGEMENT_CONFIG_DIR"] = _config_dir
    atexit.register(shutil.rmtree, _config_dir, ignore_errors=True)

# Keep IPython's profile away from the user's too, and give every process its own. The TUI's console starts an
# in-process kernel, whose history manager opens history.sqlite in this directory; xdist workers that share one file
# lock each other out, and IPython takes a locked file for a corrupt one and renames it, which fails in the worker that
# renames second. So this is set in every process, the xdist workers included, whatever they inherit.
_ipython_dir = tempfile.mkdtemp(prefix="angr-management-test-ipython-")
os.environ["IPYTHONDIR"] = _ipython_dir
atexit.register(shutil.rmtree, _ipython_dir, ignore_errors=True)

# Where a test that runs too long leaves every thread's stack before pytest-timeout kills its process (stack_dump.py
# says why). The controller makes it before it starts any worker, and the workers inherit it.
if not _xdist_worker:
    _stack_dir = tempfile.mkdtemp(prefix="angr-management-test-stacks-")
    os.environ[DIRECTORY_VARIABLE] = _stack_dir
    atexit.register(shutil.rmtree, _stack_dir, ignore_errors=True)

# How long a Textual pilot waits for the app to handle the messages pending when the wait starts. Every pilot call --
# pause, press, click -- and run_test() itself make this wait, and Textual gives it 30 s of wall-clock time with no
# setting to change it (Pilot._wait_for_screen). The macOS runner (3 cores, xdist -n 3, not forked) stalls. In job
# 117927088904 at 4e0bc3c1 it had six windows of 20 to 37 s in which no worker finished a test; in the one at 07:15
# the three tests in flight took 1.8 to 3.9 times as long as in any other macOS run, and the terminal test among them
# failed in run_test's first wait, before it had done anything. In the two macOS runs at 9e3efcd6, the tests in flight
# across one window ran 46 to 60 s over their usual time. Stopping the workers for 35 s with SIGSTOP fails tests the
# same way on Linux. With this budget, of 29 waits there that spanned such a stop, 26 took 35 to 37 s and 3 took 77 s:
# those three were one stop of all three workers as they started, on a loaded host, and they needed 42 s more after
# it ended. All 29 passed. A stall of the host from any cause, not only a SIGSTOP, lengthens a wait the same way; with
# no stop, the longest single wait on Linux was 2.4 s at a 1-minute load of about 20 on 20 cores, and 3.2 s in a run
# that began as a load spike ended (1-minute load 52 at its start, 22 at its end).
# So this budget hides nothing: a wait whose messages are really stuck still fails with the same WaitForScreenTimeout,
# two minutes in instead of half a minute, and a wait that never returns is still cut off by pytest-timeout and its
# late stack dump (stack_dump.py).
PILOT_WAIT_TIMEOUT = 120.0


def _lengthen_the_pilot_wait_budget() -> None:
    from textual.pilot import Pilot  # pylint: disable=import-outside-toplevel

    wait_for_screen = Pilot._wait_for_screen  # pylint: disable=protected-access

    async def _wait_for_screen(self: Pilot, timeout: float = PILOT_WAIT_TIMEOUT) -> bool:
        return await wait_for_screen(self, timeout)

    Pilot._wait_for_screen = _wait_for_screen  # pylint: disable=protected-access


_lengthen_the_pilot_wait_budget()

_late_stack_dump = LateStackDump()


@pytest.hookimpl(optionalhook=True)
def pytest_timeout_set_timer(item, settings):
    """
    Arm a stack dump for a tenth of the timeout before pytest-timeout fires. Returning None leaves pytest-timeout to
    arm its own timer as usual.
    """
    directory = os.environ.get(DIRECTORY_VARIABLE)
    if directory:
        _late_stack_dump.arm(directory, item.nodeid, settings.timeout * 0.9)


@pytest.hookimpl(optionalhook=True)
def pytest_timeout_cancel_timer(item):  # pylint: disable=unused-argument
    _late_stack_dump.disarm()


def pytest_terminal_summary(terminalreporter, config):
    """Print the stacks a killed test process left, on the controller, whose output is the one that is shown."""
    if hasattr(config, "workerinput") or not os.environ.get(DIRECTORY_VARIABLE):
        return
    for dump in left_behind(os.environ[DIRECTORY_VARIABLE]):
        terminalreporter.write_sep("=", "stacks of a test killed for running too long")
        terminalreporter.write(dump)


@pytest.fixture(autouse=True)
def keep_the_tui_layout():
    """
    Give every test the terminal layout it started with. The terminal app saves its tabs in Conf.tui_layout when it
    exits with a binary loaded, as a snapshot test's app does, and opens them again with the next binary, so one
    test's views would otherwise show up in the next test's screen.
    """
    from angrmanagement.config import Conf  # pylint: disable=import-outside-toplevel

    saved = Conf.tui_layout
    yield
    Conf.tui_layout = saved


@pytest.fixture(autouse=True)
def qthread_coverage(monkeypatch):
    """
    Patch QThread.run for coverage support.

    See https://github.com/coveragepy/coveragepy/issues/686 for details.
    """
    from PySide6.QtCore import QThread  # pylint: disable=import-outside-toplevel

    _base_init = QThread.__init__

    def init_with_trace(self, *args, **kwargs):
        _base_init(self, *args, **kwargs)
        self._base_run = self.run
        self.run = partial(run_with_trace, self)

    def run_with_trace(self):  # pragma: no cover
        if "coverage" in sys.modules:
            sys.settrace(threading._trace_hook)  # pyright: ignore[reportAttributeAccessIssue]
        self._base_run()

    monkeypatch.setattr(QThread, "__init__", init_with_trace)


def pytest_collection_modifyitems(config, items):
    """
    Skip the snapshot tests where pytest-textual-snapshot is not loaded. It is in the ``testing`` dependency group,
    which the upstream test image does not install, and its ``snap_compare`` fixture would otherwise fail at setup.
    """
    if config.pluginmanager.hasplugin("textual-snapshot"):
        return
    skip = pytest.mark.skip(reason="pytest-textual-snapshot is not installed")
    for item in items:
        if "snap_compare" in getattr(item, "fixturenames", ()):
            item.add_marker(skip)
