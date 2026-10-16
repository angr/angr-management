from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PySide6.QtCore import QThread

    from angrmanagement.data.library_docs import LibraryDocs
    from angrmanagement.logic.stall_watchdog import StallWatchdog
    from angrmanagement.logic.threads import UIExecutor
    from angrmanagement.logic.ui_services import UIServices
    from angrmanagement.plugins.plugin_manager import PluginManager
    from angrmanagement.ui.main_window import MainWindow
    from angrmanagement.ui.qt_executor import QExecuteCodeEventReceiver


class _GlobalInfoMeta(type):
    """
    Creates the default executor and UI services of GlobalInfo on first use.

    The default executor is created lazily so that the thread that owns it, which is the UI thread of a headless
    process, is the first thread that asks for it rather than whichever thread imported this module.
    """

    _executor: UIExecutor | None = None
    _ui_services: UIServices | None = None

    @property
    def executor(cls) -> UIExecutor:
        if cls._executor is None:
            from .threads import DirectExecutor  # pylint:disable=import-outside-toplevel

            cls._executor = DirectExecutor()
        return cls._executor

    @executor.setter
    def executor(cls, value: UIExecutor | None) -> None:
        cls._executor = value

    @property
    def ui_services(cls) -> UIServices:
        if cls._ui_services is None:
            from .ui_services import HeadlessServices  # pylint:disable=import-outside-toplevel

            cls._ui_services = HeadlessServices()
        return cls._ui_services

    @ui_services.setter
    def ui_services(cls, value: UIServices | None) -> None:
        cls._ui_services = value


class GlobalInfo(metaclass=_GlobalInfoMeta):
    """
    Global data.

    ``GlobalInfo.executor`` runs callables on the UI thread (see angrmanagement.logic.threads) and
    ``GlobalInfo.ui_services`` asks the user things (see angrmanagement.logic.ui_services). Both default to the
    headless implementations; a frontend installs its own at start-up.
    """

    gui_thread: QThread | None = None
    main_window: MainWindow | None = None
    event_receiver: QExecuteCodeEventReceiver
    daemon_inst = None
    daemon_conn = None
    client_id: str | None = None
    headless_plugin_manager: PluginManager | None = None
    library_docs: LibraryDocs = None
    autoreload = False
    stall_watchdog: StallWatchdog | None = None
