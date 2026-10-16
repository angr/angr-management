"""Installs the Qt implementations of the frontend hooks that the headless core calls through GlobalInfo."""

from __future__ import annotations

from PySide6.QtCore import QThread

from angrmanagement.config import Conf
from angrmanagement.logic import GlobalInfo

from .qt_config_adapter import QtConfigAdapter
from .qt_executor import QExecuteCodeEventReceiver, QtExecutor
from .qt_services import QtServices


def install_qt_frontend() -> None:
    """
    Make the calling thread the GUI thread and install the Qt executor, UI services and configuration adapter.

    Call it on the GUI thread once the QApplication exists. It sets ``GlobalInfo.gui_thread``, creates an event
    receiver if there is none yet (the main window creates its own as well), installs a QtExecutor as
    ``GlobalInfo.executor`` and QtServices as ``GlobalInfo.ui_services``, and makes ``Conf`` hand out QColor and
    QFont values.
    """
    GlobalInfo.gui_thread = QThread.currentThread()
    if getattr(GlobalInfo, "event_receiver", None) is None:
        GlobalInfo.event_receiver = QExecuteCodeEventReceiver()
    if not isinstance(GlobalInfo.executor, QtExecutor):
        GlobalInfo.executor = QtExecutor()
    if not isinstance(GlobalInfo.ui_services, QtServices):
        GlobalInfo.ui_services = QtServices()
    if not isinstance(Conf.frontend_adapter, QtConfigAdapter):
        Conf.set_frontend_adapter(QtConfigAdapter())
