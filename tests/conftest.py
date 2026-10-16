from __future__ import annotations

# Preload fastmcp (and therefore pydantic) before any test module imports PySide6. PySide6's
# shiboken __feature__ import hook otherwise collides with pydantic's lazy imports under pytest,
# breaking fastmcp import and causing test_mcp_server to skip depending on collection order.
import contextlib
import os
import tempfile

with contextlib.suppress(ImportError):
    import fastmcp  # noqa: F401  # pylint:disable=unused-import


import sys
import threading
from functools import partial

import pytest

# Keep the tests' configuration away from the user's: angr management reads and saves config.toml in this directory.
os.environ.setdefault("ANGR_MANAGEMENT_CONFIG_DIR", tempfile.mkdtemp(prefix="angr-management-test-config-"))


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
