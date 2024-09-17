from __future__ import annotations

__version__ = "9.2.118"


try:
    # make sure qtpy (which is used in PyQodeNG.core) is using PySide6
    import os

    os.environ["QT_API"] = "pyside6"
    import qtpy  # noqa
except ImportError:
    # qtpy is not installed
    pass
