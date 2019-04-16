import os
import importlib
import logging
from typing import Dict, Type
from types import ModuleType

from .. import config

_l = logging.getLogger(__name__)

#
# Type Hint helper
#
_T_PLUGIN_CLS_NAME = str  # plugin_class.__name__ attribute (i.e., mod.PLUGIN_CLS_NAME, not its nice display name)


class PluginManager:
    installed_plugins = {}  # type: Dict[_T_PLUGIN_CLS_NAME, Type['BasePlugin']]
    enabled_plugins = {}  # type: Dict[_T_PLUGIN_CLS_NAME, 'BasePlugin']  # Note: This has an instance, not a type

    def __init__(self, workspace, autoload=False):
        """
        Sets the workspace. Loads and initializes all plugins based on :autoload:
        :param autoload: Whether to automatically find, load, enable, and launch plugins. Defaults to False.
        """
        self._workspace = workspace
        if autoload:
            self.load_plugins()
            self.initialize_enabled_plugins()

    def load_plugins(self, plugin_dir=config.PLUGIN_PATH):
        """
        If there are subpackages in the :plugin_dir: directory, we'll assume they're plugins and load them.
        :param plugin_dir: Directory to search (non-recursively) for modules to load. Defaults to config.PLUGIN_PATH.
        """
        # TODO: Avoid permissions issues by adding a user config dir (https://github.com/angr/angr-management/issues/79)
        plugin_dirs = [filename for filename in os.listdir(plugin_dir) if
                       os.path.isdir(os.path.join(plugin_dir, filename)) and filename != '__pycache__']

        for plugin_dir in plugin_dirs:
            # TODO: get top-level package from a setting or something. This feels dirty
            mod = importlib.import_module('angrmanagement.plugins.{}'.format(plugin_dir))
            self._load_plugin_from_module(mod, mod.PLUGIN_CLS_NAME)

    def initialize_enabled_plugins(self):
        """
        After all the plugins' `__init__()` methods are called, we'll give them a chance to continue
        initializing by the time the workspace has loaded. Additionally, the `autostart()` method gives
        the plugin the option to launch a background thread.
        """
        for plugin in self.enabled_plugins.values():
            self._initialize_plugin(plugin)

    def enable_plugin(self, plugin_cls_name: _T_PLUGIN_CLS_NAME):
        """
        Enables, initializes and autostarts the plugin.

        :param plugin_cls_name:
        :return: The plugin instance
        """
        plugin_class = self.installed_plugins.get(plugin_cls_name, None)
        if plugin_class is not None:
            inst = plugin_class(plugin_manager=self, workspace=self._workspace)
            self.enabled_plugins[plugin_cls_name] = inst
            self._initialize_plugin(inst)
        else:
            _l.error("Plugin '{}' not installed!".format(plugin_cls_name))

    def disable_plugin(self, plugin_cls_name: _T_PLUGIN_CLS_NAME):
        """
        Stops any running threads and disables the plugin

        :param plugin_cls_name: The class name of the plugin to stop
        """
        plugin = self.enabled_plugins.get(plugin_cls_name, None)  # type: 'BasePlugin'
        if plugin is not None:
            self.stop_plugin_thread(plugin)
            plugin.on_disable()
            self.enabled_plugins.pop(plugin_cls_name, None)
        else:
            _l.error("Plugin '{}' not installed!".format(plugin_cls_name))

    def stop_all_plugin_threads(self):
        """
        Ask all the plugins to stop. See `PluginManager.stop_plugin()`.
        """
        for plugin in self.enabled_plugins.values():
            self.stop_plugin_thread(plugin)

    def stop_plugin_thread(self, plugin: 'BasePlugin'):
        """
        Ask the plugin to stop. After three seconds, it's terminated.
        """
        # TODO: The plugin wait time here should be a user or even plugin setting
        if plugin.isRunning():
            _l.info("Stopping plugin: {}".format(plugin.get_display_name()))
            plugin.sync_stop_thread()
            plugin.wait(3000)

    #
    # Private Methods
    #

    def _initialize_plugin(self, plugin: 'BasePlugin'):
        plugin.register_callbacks()
        plugin.register_other()
        plugin.autostart()

    def _register_installed(self, cls: Type['BasePlugin']):
        """
        Adds the plugin to our installed dict.
        """
        if cls.__name__ in self.installed_plugins.keys():
            _l.warning("Class name '{}' already in use. Previous plugin hidden...".format(cls.__name__))
        self.installed_plugins[cls.__name__] = cls

    def _load_plugin_from_module(self, module: ModuleType, class_name: str):
        """
        Denote a plugin as installed and instantiate (enable) it if it `is_autoenabled`.
        """
        if class_name not in self.enabled_plugins.keys():
            plugin_class = getattr(module, class_name)  # type: Type['BasePlugin']
            self._register_installed(plugin_class)

            if plugin_class.is_autoenabled:
                self.enable_plugin(class_name)

    def _load_plugin_from_package(self, pkg: str, modules: str, class_name: str):  # pylint: disable=unused-variable
        """
        Load a plugin that's been installed in a separate PyPi package
        """
        # TODO: Handle errors gracefully
        mod = importlib.import_module(modules, package=pkg)
        self._load_plugin_from_module(mod, class_name)
