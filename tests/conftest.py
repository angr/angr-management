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
