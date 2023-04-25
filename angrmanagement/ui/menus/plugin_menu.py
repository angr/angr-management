from .menu import Menu, MenuEntry


class PluginMenu(Menu):
    def __init__(self, main_window):
        super().__init__("&Plugins", parent=main_window)

        self.entries.extend([MenuEntry("&Manage Plugins...", main_window.open_load_plugins_dialog)])
