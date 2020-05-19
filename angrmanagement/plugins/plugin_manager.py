import functools
from typing import Optional, List, Type, Union, TYPE_CHECKING
import logging
import os

from PySide2.QtGui import QColor

from angrmanagement.ui.menus.menu import MenuEntry, MenuSeparator
from angrmanagement.ui.toolbars.toolbar import ToolbarAction
from angrmanagement.daemon.url_handler import register_url_action, UrlActionBinaryAware
from angrmanagement.daemon.client import DaemonClient
from ..config import Conf
from . import load_plugins_from_dir
from .base_plugin import BasePlugin

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


l = logging.getLogger(__name__)

# The plugin manager can be initialized in two modes:
# - UI mode, where workspace is not None
# - headless mode, where workspace is None, and any plugin that requires workspace will not be initialized
#
# Plugins can be in two states:
# - Loaded, but inactive. In this, the class is present in .loaded_plugins but there is nothing in .active_plugins
# - Activated. In this, there is an instance of the class in .active_plugins
#
# ...so this class has functions to transition plugins into and between these states.
#
# The actual process of excavating a process from the filesystem into a python class ("loading") needs to be dealt
# with before anything touches this class. There are functions to do that in the plugins package but they need to be
# tied to the user's settings related to loading paths and activation. Presently this is split between MainWindow (the
# first-boot autoload part) and the LoadPlugins dialog (the extra loading and tweaking activation)

class PluginManager:
    def __init__(self, workspace: Optional['Workspace']):
        self.workspace = workspace
        # should one or both of these be ObjectContainers? I think no since we should be synchronizing on models, not
        # views/controllers. not super clear... that's not a hard and fast rule
        self.loaded_plugins = []  # type: List[Type[BasePlugin]]
        self.active_plugins = []  # type: List[BasePlugin]

    def discover_and_initialize_plugins(self):
        os.environ['AM_BUILTIN_PLUGINS'] = os.path.dirname(__file__)
        blacklist = Conf.plugin_blacklist.split(',')
        for search_dir in Conf.plugin_search_path.split(':'):
            search_dir = os.path.expanduser(search_dir)
            search_dir = os.path.expandvars(search_dir)
            for plugin_or_exception in load_plugins_from_dir(search_dir):
                if isinstance(plugin_or_exception, Exception):
                    l.info(plugin_or_exception)
                elif not any(dont in repr(plugin_or_exception) for dont in blacklist):
                    plugin_or_exception: Type[BasePlugin]
                    if (plugin_or_exception.REQUIRE_WORKSPACE and self.workspace is not None) \
                            or not plugin_or_exception.REQUIRE_WORKSPACE:
                        self.activate_plugin(plugin_or_exception)
                else:
                    if (plugin_or_exception.REQUIRE_WORKSPACE and self.workspace is not None) \
                            or not plugin_or_exception.REQUIRE_WORKSPACE:
                        self.load_plugin(plugin_or_exception)
                        l.info("Blacklisted plugin %s", plugin_or_exception.get_display_name())

    def load_plugin(self, plugin_cls: Type[BasePlugin]):
        if plugin_cls in self.loaded_plugins:
            return
        if type(plugin_cls) is not type or not issubclass(plugin_cls, BasePlugin):
            raise TypeError("Cannot load a plugin which is not a BasePlugin subclass")
        if hasattr(plugin_cls, '_%s__i_hold_this_abstraction_token' % plugin_cls.__name__):
            raise TypeError("Cannot load an abstract plugin")
        if plugin_cls.REQUIRE_WORKSPACE and self.workspace is None:
            raise RuntimeError("Cannot load plugin %s in headless mode.")
        self.loaded_plugins.append(plugin_cls)

    def activate_plugin(self, plugin_cls: Type[BasePlugin]):
        self.load_plugin(plugin_cls)  # just to be sure, also perform the sanity checks
        if self.get_plugin_instance(plugin_cls) is not None:
            return

        try:
            plugin = plugin_cls(self.workspace)
            self.active_plugins.append(plugin)
            plugin.__cached_toolbar_actions = []  # a hack, lol. really this could be a mapping on PluginManager but idc
            plugin.__cached_menu_actions = []  # as above

            if self.workspace is not None:
                for idx, (icon, tooltip) in enumerate(plugin_cls.TOOLBAR_BUTTONS):
                    action = ToolbarAction(icon, 'plugin %s toolbar %d' % (plugin_cls, idx), tooltip, functools.partial(self._dispatch_single, plugin, BasePlugin.handle_click_toolbar, False, idx))
                    plugin.__cached_toolbar_actions.append(action)
                    self.workspace._main_window._file_toolbar.add(action)

                if plugin_cls.MENU_BUTTONS:
                    self.workspace._main_window._plugin_menu.add(MenuSeparator())
                for idx, text in enumerate(plugin_cls.MENU_BUTTONS):
                    action = MenuEntry(text, functools.partial(self._dispatch_single, plugin, BasePlugin.handle_click_menu, False, idx))
                    plugin.__cached_menu_actions.append(action)
                    self.workspace._main_window._plugin_menu.add(action)

                for dview in self.workspace.view_manager.views_by_category['disassembly']:
                    plugin.instrument_disassembly_view(dview)

                for action in plugin_cls.URL_ACTIONS:
                    DaemonClient.register_handler(action,
                                                  functools.partial(self._dispatch_single,
                                                                    plugin,
                                                                    BasePlugin.handle_url_action,
                                                                    False,
                                                                    action
                                                                    )
                                                  )

            for action in plugin_cls.URL_ACTIONS:
                register_url_action(action, UrlActionBinaryAware)

        except Exception:
            l.warning("Plugin %s failed to activate:", plugin_cls.get_display_name(),
                      exc_info=True)
        else:
            l.info("Activated plugin %s", plugin_cls.get_display_name())

    def get_plugin_instance(self, plugin_cls: Type[BasePlugin]) -> Optional[BasePlugin]:
        instances = [plugin for plugin in self.active_plugins if type(plugin) is plugin_cls]
        if len(instances) == 0:
            return None
        if len(instances) > 1:
            l.error("Somehow there is more than one instance of %s active?" % plugin_cls.get_display_name())
        return instances[0]

    def deactivate_plugin(self, plugin: Union[BasePlugin, Type[BasePlugin]]):
        # this method should work on both instances and classes
        if type(plugin) is type:
            plugin = self.get_plugin_instance(plugin)
        else:
            plugin = plugin
        if plugin not in self.active_plugins:
            return

        for action in plugin.__cached_toolbar_actions:
            self.workspace._main_window._file_toolbar.remove(action)
        for action in plugin.__cached_menu_actions:
            self.workspace._main_window._plugin_menu.remove(action)

        try:
            plugin.teardown()
        except Exception:
            l.warning("Plugin %s errored during removal. The UI may be unstable.", plugin.get_display_name(),
                      exc_info=True)
        self.active_plugins.remove(plugin)

    #
    # Dispatchers
    #

    def _dispatch(self, func, sensitive, *args):
        for plugin in list(self.active_plugins):
            custom = getattr(plugin, func.__name__)
            if custom.__func__ is not func:
                try:
                    res = custom(*args)
                except Exception as e:
                    self._handle_error(plugin, func, sensitive, e)
                else:
                    yield res

        return None

    def _dispatch_single(self, plugin, func, sensitive, *args):
        custom = getattr(plugin, func.__name__)
        try:
            return custom(*args)
        except Exception as e:
            self._handle_error(plugin, func, sensitive, e)
            return None

    def _handle_error(self, plugin, func, sensitive, exc):
        self.workspace.log("Plugin %s errored during %s" % (plugin.get_display_name(), func.__name__))
        self.workspace.log(exc)
        if sensitive:
            self.workspace.log("Deactivating %s for error during sensitive operation" % plugin.get_display_name())
            self.deactivate_plugin(plugin)

    def color_insn(self, addr, selected) -> Optional[QColor]:
        for res in self._dispatch(BasePlugin.color_insn, True, addr, selected):
            if res is not None:
                return res
        return None

    def color_block(self, addr) -> Optional[QColor]:
        for res in self._dispatch(BasePlugin.color_block, True, addr):
            if res is not None:
                return res
        return None

    def color_func(self, func) -> Optional[QColor]:
        for res in self._dispatch(BasePlugin.color_func, True, func):
            if res is not None:
                return res
        return None

    def draw_insn(self, qinsn, painter):
        for _ in self._dispatch(BasePlugin.draw_insn, True, qinsn, painter):
            pass

    def draw_block(self, qblock, painter):
        for _ in self._dispatch(BasePlugin.draw_block, True, qblock, painter):
            pass

    def instrument_disassembly_view(self, dview):
        for _ in self._dispatch(BasePlugin.instrument_disassembly_view, False, dview):
            pass

    def handle_click_insn(self, qinsn, event):
        for res in self._dispatch(BasePlugin.handle_click_insn, False, qinsn, event):
            if res:
                return True
        return False

    def handle_click_block(self, qblock, event):
        for res in self._dispatch(BasePlugin.handle_click_block, False, qblock, event):
            if res:
                return True
        return False

    def build_context_menu_insn(self, insn):
        for res in self._dispatch(BasePlugin.build_context_menu_insn, False, insn):
            yield from res

    def get_func_column(self, idx):
        for plugin in self.active_plugins:
            if idx >= len(plugin.FUNC_COLUMNS):
                idx -= len(plugin.FUNC_COLUMNS)
            else:
                return plugin.FUNC_COLUMNS[idx]
        raise IndexError("Not enough columns")

    def count_func_columns(self):
        return sum((len(plugin.FUNC_COLUMNS) for plugin in self.active_plugins))

    def extract_func_column(self, func, idx):
        for plugin in self.active_plugins:
            if idx > len(plugin.FUNC_COLUMNS):
                idx -= len(plugin.FUNC_COLUMNS)
            else:
                try:
                    return plugin.extract_func_column(func, idx)
                except Exception as e:
                    # this should really be a "sensitive" operation but like
                    self.workspace.log(e)
                    self.workspace.log("PLEASE FIX YOUR PLUGIN AHHHHHHHHHHHHHHHHH")
                    return 0, ''
        raise IndexError("Not enough columns")
