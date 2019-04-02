from .plugin_manager import PluginManager


class BasePlugin:
    _plugin_manager = None

    # TODO: defaults should be read from config file... eventually
    def __init__(self, plugin_manager, workspace):
        self._plugin_manager = plugin_manager
        self._workspace = workspace
        print("Loaded TestPlugin")

    def register_theme_callbacks(self):
        self._workspace.set_cb_function_backcolor(self.func_back_color)
        self._workspace.set_cb_insn_backcolor(self.insn_backcolor)

    def register_data_callbacks(self):
        pass

    def register_other(self):
        pass

    def insn_backcolor(self, addr, selected):
        return None, None, None

    def func_back_color(self, func):
        return 255, 255, 255


PluginManager.register_default('base', BasePlugin)
