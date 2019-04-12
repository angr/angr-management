from typing import Dict
_T_PLUGIN_LIST = Dict[str, 'BasePlugin']

class PluginManager:
    default_plugins = {}  # type: _T_PLUGIN_LIST
    user_plugins = {}  # type: _T_PLUGIN_LIST

    def __init__(self, workspace):
        self._workspace = workspace
        self._loaded_plugins = {}  # type: _T_PLUGIN_LIST

        self.load_default_plugins()

    @property
    def loaded_plugins(self) -> _T_PLUGIN_LIST:
        return self._loaded_plugins

    def load_default_plugins(self):
        for name, cls in PluginManager.default_plugins.items():
            self._loaded_plugins[name] = cls(plugin_manager=self, workspace=self._workspace)

    def initialize_all(self):
        for plugin in self._loaded_plugins.values():
            plugin.register_callbacks()
            plugin.register_other()
            plugin.autostart()

    def stop_all(self):
        for plugin in self._loaded_plugins.values():
            if plugin.isRunning():
                plugin.sync_stop()
                plugin.wait()

    def load_plugin(self, pkg, modules, class_name):
        import importlib

        #mod = importlib.import_module('angr_plugins.chess_plugin', package='frontend')
        # cls = getattr(mod, 'ChessPlugin')
        # c = cls()
        mod = importlib.import_module(modules, package=pkg)
        cls = getattr(mod, class_name)
        ####################
        # TODO: Maybe use a JSON file to define all this?
        name = class_name
        try:
            name = getattr(mod, 'PLUGIN_NAME')
        except AttributeError:
            pass
        ####################
        self.user_plugins[name] = cls(plugin_manager=self, workspace=self._workspace)

    @staticmethod
    def register_default(name, cls):
        if name in PluginManager.default_plugins:
            raise Exception("%s is already set as the default for %s" % (PluginManager.default_plugins[name], name))
        PluginManager.default_plugins[name] = cls
