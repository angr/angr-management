"""Installs the Qt implementations of the frontend hooks that the headless core calls through GlobalInfo."""

from __future__ import annotations

from PySide6.QtCore import QThread

from angrmanagement.logic import GlobalInfo

from .qt_executor import QExecuteCodeEventReceiver, QtExecutor
from .qt_services import QtServices


def install_qt_frontend() -> None:
    """
    Make the calling thread the GUI thread and install the Qt executor and UI services.

    Call it on the GUI thread once the QApplication exists. It sets ``GlobalInfo.gui_thread``, creates an event
    receiver if there is none yet (the main window creates its own as well), and installs a QtExecutor as
    ``GlobalInfo.executor`` and QtServices as ``GlobalInfo.ui_services``.
    """
    GlobalInfo.gui_thread = QThread.currentThread()
    if getattr(GlobalInfo, "event_receiver", None) is None:
        GlobalInfo.event_receiver = QExecuteCodeEventReceiver()
    if not isinstance(GlobalInfo.executor, QtExecutor):
        GlobalInfo.executor = QtExecutor()
    if not isinstance(GlobalInfo.ui_services, QtServices):
        GlobalInfo.ui_services = QtServices()
