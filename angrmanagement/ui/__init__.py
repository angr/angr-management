"""
The Qt frontend of angr management.

Importing it makes ``Conf`` hand out Qt values (QColor, QFont) for the configuration's colour and font entries,
because modules in this package read them as soon as they are imported.
"""

from __future__ import annotations

from angrmanagement.config import Conf

from .qt_config_adapter import QtConfigAdapter

if not isinstance(Conf.frontend_adapter, QtConfigAdapter):
    Conf.set_frontend_adapter(QtConfigAdapter())
