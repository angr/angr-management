"""
Run test code in a fresh interpreter in which PySide6 cannot be imported.

The test processes themselves always import PySide6 (conftest.py does), so code that must work without it runs in a
subprocess. The script given to :func:`run_without_qt` runs after a meta-path hook that refuses PySide6 and the other
Qt bindings, and it reports back by assigning a JSON-serialisable ``RESULT``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

BLOCKED_PACKAGES = ("PySide6", "shiboken6", "PySide6QtAds", "qtpy", "qtawesome", "pyqodeng", "qtconsole")

_PRELUDE = """
import importlib.abc
import json
import sys

BLOCKED = {blocked!r}


class _BlockQt(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in BLOCKED:
            raise ImportError(f"{{fullname}} is blocked in this headless test", name=fullname)
        return None


sys.meta_path.insert(0, _BlockQt())
for _name in ("PySide6", "PySide6.QtCore", "PySide6.QtGui", "PySide6.QtWidgets"):
    sys.modules[_name] = None

# the hook must hold, or this test proves nothing
try:
    import PySide6.QtCore  # noqa: F401
except ImportError:
    pass
else:
    raise AssertionError("PySide6 is importable although it is blocked")
try:
    import qtpy  # noqa: F401
except ImportError:
    pass
else:
    raise AssertionError("qtpy is importable although it is blocked")


def qt_modules_loaded():
    return sorted(name for name, mod in sys.modules.items() if mod is not None and name.split(".")[0] in BLOCKED)


RESULT = None
"""

_EPILOGUE = """
RESULT = {"result": RESULT, "qt_modules_loaded": qt_modules_loaded()}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(RESULT, f)
"""


def run_without_qt(script: str, timeout: float = 600.0, env: dict[str, str] | None = None) -> dict:
    """
    Run ``script`` in a new interpreter with the Qt bindings blocked.

    :returns: ``{"result": <the script's RESULT>, "qt_modules_loaded": [<Qt modules that got imported>]}``.
    :raises AssertionError: If the interpreter fails; the message carries its output.
    """
    source = _PRELUDE.format(blocked=BLOCKED_PACKAGES) + textwrap.dedent(script) + _EPILOGUE
    with tempfile.TemporaryDirectory(prefix="am-headless-test-") as workdir:
        script_path = os.path.join(workdir, "headless_script.py")
        result_path = os.path.join(workdir, "result.json")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(source)
        child_env = dict(os.environ)
        child_env["ANGR_MANAGEMENT_CONFIG_DIR"] = os.path.join(workdir, "config")
        child_env.pop("QT_QPA_PLATFORM", None)
        if env:
            child_env.update(env)
        # -P: never put the script's directory (or a worktree) ahead of the installed package
        proc = subprocess.run(
            [sys.executable, "-P", script_path, result_path],
            cwd=workdir,
            env=child_env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0 or not os.path.exists(result_path):
            raise AssertionError(
                f"the headless interpreter exited with {proc.returncode}\n"
                f"--- stdout ---\n{proc.stdout[-5000:]}\n--- stderr ---\n{proc.stderr[-10000:]}"
            )
        with open(result_path, encoding="utf-8") as f:
            return json.load(f)
