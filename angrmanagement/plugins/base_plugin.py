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
        self._workspace.set_cb_insn_select_backcolor(self.insn_select_backcolor)

    def register_data_callbacks(self):
        pass

    def register_other(self):
        pass

    def insn_backcolor(self, addr):
        return None, None, None

    def insn_select_backcolor(self, addr):
        return 0xef, 0xbf, 0xba

    def func_back_color(self, func):
        if func.name is None or func.name is '':
            return 255, 255, 255
        # TODO - Hack for a bug. See: https://github.com/angr/cle/pull/175. Won't need None check when merged.
        elif func.binary._entry is not None and func.addr == func.binary.entry:
            return 0xe5, 0xfb, 0xff  # light blue
        else:
            return 255, 255, 255


PluginManager.register_default('base', BasePlugin)
