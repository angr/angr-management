from typing import Dict


class PluginManager:
    default_plugins = {}  # type: Dict[str, 'BasePlugin']

    def __init__(self, workspace):
        self._workspace = workspace
        self._plugins = {}  # type: Dict[str, 'BasePlugin']

        self.load_default_plugins()

    def load_default_plugins(self):
        for name, cls in PluginManager.default_plugins.items():
            self._plugins[name] = cls(plugin_manager=self, workspace=self._workspace)

    def initialize_all(self):
        for plugin in self._plugins.values():
            plugin.register_callbacks()
            plugin.register_other()
            plugin.autostart()

    def stop_all(self):
        for plugin in self._plugins.values():
            if plugin.isRunning():
                plugin.sync_stop()
                plugin.wait()

    @staticmethod
    def register_default(name, cls):
        if name in PluginManager.default_plugins:
            raise Exception("%s is already set as the default for %s" % (PluginManager.default_plugins[name], name))
        PluginManager.default_plugins[name] = cls
