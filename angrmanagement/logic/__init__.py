from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angrmanagement.data.library_docs import LibraryDocs
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
