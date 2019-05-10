from .menu import Menu, MenuEntry, MenuSeparator


class PluginMenu(Menu):
    def __init__(self, main_window):
        super().__init__("&Plugins", parent=main_window)

        self.entries.extend([
            MenuEntry('&Load Plugin', main_window.open_load_plugins_dialog)
        ])
