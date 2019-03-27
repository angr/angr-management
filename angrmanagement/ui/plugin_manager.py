

class BaseThemePlugin:
    def __init__(self, workspace):
        print("Loaded TestPlugin")
        self._workspace = workspace
        self._workspace.set_cb_function_backcolor(self.func_back_color)
        self._workspace.set_cb_insn_backcolor(self.insn_backcolor)
        self._workspace.set_cb_insn_select_backcolor(self.insn_select_backcolor)

    def insn_backcolor(self, addr):
        return None, None, None

    def insn_select_backcolor(self, addr):
        return 0xef, 0xbf, 0xba

    def func_back_color(self, func):
        if func.name is None or func.name is '':
            return 255, 255, 255
        # HACK for a bug. See: https://github.com/angr/cle/pull/175. Won't need None check when merged.
        elif func.binary._entry is not None and func.addr == func.binary.entry:
            return 0xe5, 0xfb, 0xff  # light blue
        else:
            return 255, 255, 255


class TestTheme(BaseThemePlugin):
    def insn_backcolor(self, addr):
        return 0xd6, 0xff, 0xd6


class PluginManager:
    def __init__(self, workspace):
        self._workspace = workspace
        self._plugins = {}

    def load_all(self):
        print("Loading all plugins")
        self._plugins['theme'] = BaseThemePlugin(self._workspace)
        self._plugins['theme'] = TestTheme(self._workspace)
