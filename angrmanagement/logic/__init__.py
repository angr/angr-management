from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angrmanagement.data.library_docs import LibraryDocs
    from angrmanagement.logic.threads import ExecuteCodeEvent
    from angrmanagement.plugins.plugin_manager import PluginManager
    from angrmanagement.ui.main_window import MainWindow


class GlobalInfo:
    gui_thread = None
    main_window: MainWindow = None
    daemon_inst = None
    daemon_conn = None
    headless_plugin_manager: PluginManager = None
    library_docs: LibraryDocs = None
    autoreload = False
    is_test = False

    events: list[ExecuteCodeEvent] = []

    @classmethod
    def add_event_during_test(cls, event: ExecuteCodeEvent) -> None:
        """
        Add an ExecuteCode event to the event queue during tests. Events in the queue will be picked up by a manually
        crafted event loop and executed one by one (see tests/common.py).
        """
        cls.events.append(event)
