"""
The core of angr management imports without PySide6.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from headless import run_without_qt  # pylint: disable=import-error

IMPORT_SCRIPT = """
import importlib
import pkgutil

PACKAGES = [
    "angrmanagement.config",
    "angrmanagement.data",
    "angrmanagement.logic",
    "angrmanagement.mcp",
    "angrmanagement.daemon",
    "angrmanagement.utils",
]
MODULES = [
    "angrmanagement.plugins.base_plugin",
    "angrmanagement.plugins.plugin_manager",
    "angrmanagement.tui",
    "angrmanagement.tui.__main__",
]

names = list(MODULES)
for package in PACKAGES:
    names.append(package)
    module = importlib.import_module(package)
    names.extend(info.name for info in pkgutil.walk_packages(module.__path__, package + "."))

imported, failed, optional_missing = [], {}, {}
for name in names:
    try:
        importlib.import_module(name)
    except ModuleNotFoundError as ex:
        # a missing optional dependency (fastmcp, say) is not what this test is about; a blocked Qt binding is
        if ex.name and ex.name.split(".")[0] in BLOCKED:
            failed[name] = repr(ex)
        else:
            optional_missing[name] = repr(ex)
    except Exception as ex:  # noqa: BLE001
        failed[name] = repr(ex)
    else:
        imported.append(name)

RESULT = {"imported": imported, "failed": failed, "optional_missing": optional_missing}
"""


class TestHeadlessImport(unittest.TestCase):
    """Import every core module in an interpreter that cannot import PySide6."""

    def test_core_imports_without_pyside6(self):
        outcome = run_without_qt(IMPORT_SCRIPT)
        result = outcome["result"]

        assert result["failed"] == {}, result["failed"]
        assert outcome["qt_modules_loaded"] == []
        for name in (
            "angrmanagement.config",
            "angrmanagement.config.config_manager",
            "angrmanagement.data.instance",
            "angrmanagement.data.jobs.cfg_generation",
            "angrmanagement.data.jobs.loading",
            "angrmanagement.logic.jobmanager",
            "angrmanagement.logic.threads",
            "angrmanagement.logic.headless_workspace",
            "angrmanagement.plugins.base_plugin",
            "angrmanagement.plugins.plugin_manager",
            "angrmanagement.mcp",
            "angrmanagement.daemon",
            "angrmanagement.utils.io",
        ):
            assert name in result["imported"], name
        # the walk must have found the job modules, or it proves little
        assert sum(name.startswith("angrmanagement.data.jobs.") for name in result["imported"]) >= 20


class TestTuiEntryPoint(unittest.TestCase):
    """am-tui says what is missing: Textual is in the tui extra, not a dependency of angr management."""

    def test_reports_the_missing_extra(self):
        from angrmanagement.tui.__main__ import main  # pylint: disable=import-outside-toplevel

        err = io.StringIO()
        # a None entry in sys.modules makes the import raise ImportError, as a missing package does
        with patch.dict("sys.modules", {"textual": None}), redirect_stderr(err):
            assert main() == 2
        assert "angr-management[tui]" in err.getvalue()

    def test_reports_that_the_frontend_is_not_written_yet(self):
        from angrmanagement.tui.__main__ import main  # pylint: disable=import-outside-toplevel

        err = io.StringIO()
        with redirect_stderr(err):
            assert main() == 2
        assert "not implemented yet" in err.getvalue()


if __name__ == "__main__":
    unittest.main()
