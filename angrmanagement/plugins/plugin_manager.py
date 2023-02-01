# pylint:disable=unused-private-member
import functools
import logging
import os
from typing import TYPE_CHECKING, Dict, Optional, Type, Union

from angrmanagement.config import Conf, save_config
from angrmanagement.config.config_manager import ENTRIES
from angrmanagement.daemon.client import DaemonClient
from angrmanagement.daemon.url_handler import UrlActionBinaryAware, register_url_action
from angrmanagement.ui.menus.menu import MenuEntry, MenuSeparator
from angrmanagement.ui.toolbars.toolbar_action import ToolbarAction

from .base_plugin import BasePlugin
from .load import load_plugin_descriptions_from_dir, load_plugins_from_file

if TYPE_CHECKING:
    from PySide6.QtGui import QColor

    from angrmanagement.ui.widgets.qblock import QBlock
    from angrmanagement.ui.workspace import Workspace

    from .plugin_description import PluginDescription


log = logging.getLogger(__name__)


class PluginManager:
    """
    The plugin manager can be initialized in two modes:
    - UI mode, where workspace is not None
    - headless mode, where workspace is None, and any plugin that requires workspace will not be initialized

    Plugins can be in two states:
    - Loaded, but inactive. In this, the class is present in .loaded_plugins but there is nothing in .active_plugins
    - Activated. In this, there is an instance of the class in .active_plugins

    ...so this class has functions to transition plugins into and between these states.

    The actual process of excavating a process from the filesystem into a python class ("loading") needs to be dealt
    with before anything touches this class. There are functions to do that in the plugins package but they need to be
    tied to the user's settings related to loading paths and activation. Presently this is split between MainWindow (the
    first-boot autoload part) and the LoadPlugins dialog (the extra loading and tweaking activation)
    """

    def __init__(self, workspace: Optional["Workspace"]):
        self.workspace = workspace
        # should one or both of these be ObjectContainers? I think no since we should be synchronizing on models, not
        # views/controllers. not super clear... that's not a hard and fast rule
        self.loaded_plugins: Dict[str, PluginDescription] = {}
        self.active_plugins: Dict[str, BasePlugin] = {}

    def discover_and_initialize_plugins(self):
        os.environ["AM_BUILTIN_PLUGINS"] = os.path.dirname(__file__)
        enabled_plugins = [plugin_.strip() for plugin_ in Conf.enabled_plugins.split(",") if plugin_.strip()]
        for search_dir in Conf.plugin_search_path.split(":"):
            search_dir = os.path.expanduser(search_dir)
            search_dir = os.path.expandvars(search_dir)

            # load plugin descriptions
            dir_and_descs = load_plugin_descriptions_from_dir(search_dir)
            for _, desc in dir_and_descs:
                if desc.shortname in self.loaded_plugins:
                    log.warning(
                        "Plugin shortname conflict: %s and %s have the same shortname %s.",
                        self.loaded_plugins[desc.shortname].plugin_file_path,
                        desc.plugin_file_path,
                        desc.shortname,
                    )
                    continue
                self.loaded_plugins[desc.shortname] = desc

            # activate all enabled plugins
            for plugin_name, desc in self.loaded_plugins.items():
                # don't reactivate already active plugins
                if plugin_name in self.active_plugins:
                    continue

                plugin_conf_key = f"plugin_{desc.name}_enabled"

                # see if the plugin is enabled or not
                if any(
                    (plugin in desc.name or plugin.lower() in desc.shortname.lower()) for plugin in enabled_plugins
                ) and not (hasattr(Conf, plugin_conf_key) and getattr(Conf, plugin_conf_key) is False):
                    # see if we can't load this plugin because headless mode
                    if self.workspace is None and desc.require_workspace:
                        if desc.has_url_actions:
                            basedir = os.path.join(os.path.dirname(desc.plugin_file_path))
                            for plugin_cls in load_plugins_from_file(os.path.join(basedir, desc.entrypoints[0])):
                                if isinstance(plugin_cls, Exception):
                                    log.warning("Exception occurred during plugin loading: %s", plugin_cls)
                                else:
                                    plugin_cls: Type[BasePlugin]
                                    for action in plugin_cls.URL_ACTIONS:
                                        register_url_action(action, UrlActionBinaryAware)
                    else:
                        self.activate_plugin_by_name(desc.shortname)

    def verify_plugin_class(self, plugin_cls: Type[BasePlugin]):
        if type(plugin_cls) is not type or not issubclass(plugin_cls, BasePlugin):
            raise TypeError("Cannot load a plugin which is not a BasePlugin subclass")
        if hasattr(plugin_cls, "_%s__i_hold_this_abstraction_token" % plugin_cls.__name__):
            raise TypeError("Cannot load an abstract plugin")
        if plugin_cls.REQUIRE_WORKSPACE and self.workspace is None:
            raise RuntimeError("Cannot load plugin %s in headless mode.")

    def activate_plugin_by_name(self, shortname: str):
        desc = self.loaded_plugins[shortname]
        basedir = os.path.join(os.path.dirname(desc.plugin_file_path))
        for plugin_cls in load_plugins_from_file(os.path.join(basedir, desc.entrypoints[0])):
            if isinstance(plugin_cls, Exception):
                log.warning("Exception occurred during plugin loading: %s", plugin_cls, exc_info=True)
            else:
                self.activate_plugin(desc.shortname, plugin_cls)

    def activate_plugin(self, shortname: str, plugin_cls: Type[BasePlugin]):
        self.verify_plugin_class(plugin_cls)  # perform the sanity checks
        if self.get_plugin_instance(plugin_cls) is not None:
            return

        try:
            plugin = plugin_cls(self.workspace)
            self.active_plugins[shortname] = plugin
            plugin.__cached_status_bar_widgets = []
            plugin.__cached_toolbar_actions = []  # a hack, lol. really this could be a mapping on PluginManager but idc
            plugin.__cached_menu_actions = []  # as above

            if self.workspace is not None:
                self._register_status_bar_widgets(plugin)
                self._register_toolbar_actions(plugin_cls, plugin)
                self._register_menu_buttons(plugin_cls, plugin)

                for dview in self.workspace.view_manager.views_by_category["disassembly"]:
                    plugin.instrument_disassembly_view(dview)
                for cview in self.workspace.view_manager.views_by_category["pseudocode"]:
                    plugin.instrument_code_view(cview)

                self._register_url_actions(plugin_cls, plugin)
                self._register_configuration_entries(plugin_cls)

            for action in plugin_cls.URL_ACTIONS:
                register_url_action(action, UrlActionBinaryAware)

        except Exception:  # pylint: disable=broad-except
            log.warning("Plugin %s failed to activate:", plugin_cls.get_display_name(), exc_info=True)
        else:
            log.info("Activated plugin %s", plugin_cls.get_display_name())

    def save_enabled_plugins_to_config(self):
        # pylint: disable=assigning-non-slot
        Conf.enabled_plugins = ",".join(self.active_plugins.keys())
        save_config()

    def _register_status_bar_widgets(self, plugin: BasePlugin) -> None:
        gen = plugin.status_bar_permanent_widgets()
        if gen is not None:
            for widget in gen:
                self.workspace.main_window.statusBar().addPermanentWidget(widget)
                widget.show()
                plugin.__cached_status_bar_widgets.append(widget)

    def _register_toolbar_actions(self, plugin_cls: Type[BasePlugin], plugin: BasePlugin) -> None:
        for idx, (icon, tooltip) in enumerate(plugin_cls.TOOLBAR_BUTTONS):
            action = ToolbarAction(
                icon,
                "plugin %s toolbar %d" % (plugin_cls, idx),
                tooltip,
                functools.partial(self._dispatch_single, plugin, BasePlugin.handle_click_toolbar, False, idx),
            )
            plugin.__cached_toolbar_actions.append(action)
            self.workspace._main_window._file_toolbar.add(action)

    def _register_menu_buttons(self, plugin_cls: Type[BasePlugin], plugin: BasePlugin) -> None:
        if plugin_cls.MENU_BUTTONS:
            self.workspace._main_window._plugin_menu.add(MenuSeparator())
        for idx, text in enumerate(plugin_cls.MENU_BUTTONS):
            action = MenuEntry(
                text, functools.partial(self._dispatch_single, plugin, BasePlugin.handle_click_menu, False, idx)
            )
            plugin.__cached_menu_actions.append(action)
            self.workspace._main_window._plugin_menu.add(action)

    def _register_url_actions(self, plugin_cls: Type[BasePlugin], plugin: BasePlugin) -> None:
        for action in plugin_cls.URL_ACTIONS:
            DaemonClient.register_handler(
                action, functools.partial(self._dispatch_single, plugin, BasePlugin.handle_url_action, False, action)
            )

    @staticmethod
    def _register_configuration_entries(plugin_cls: Type[BasePlugin]) -> None:
        new_entries_added = False
        for ent in plugin_cls.CONFIG_ENTRIES:
            if ent not in ENTRIES:
                # if a plugin is disabled and then enabled, the entry may already exist?
                ENTRIES.append(ent)
                new_entries_added = True

        if new_entries_added:
            # reload configuration manager so that it's aware of newly added entries
            Conf.reinterpet()

    def get_plugin_instance_by_name(self, shortname: str) -> Optional[BasePlugin]:
        instances = [plugin for key, plugin in self.active_plugins.items() if key == shortname]
        if not instances:
            return None
        if len(instances) > 1:
            log.error("Somehow there is more than one instance of %s active?", shortname)
        return instances[0]

    def get_plugin_instance(self, plugin_cls: Type[BasePlugin]) -> Optional[BasePlugin]:
        instances = [plugin for plugin in self.active_plugins.values() if type(plugin) is plugin_cls]
        if len(instances) == 0:
            return None
        if len(instances) > 1:
            log.error("Somehow there is more than one instance of %s active?", plugin_cls.get_display_name())
        return instances[0]

    def deactivate_plugin_by_name(self, shortname: str):
        for key, plugin in self.active_plugins.items():
            if key == shortname:
                self.deactivate_plugin(plugin)
                break

    def deactivate_plugin(self, plugin: Union[BasePlugin, Type[BasePlugin]]):
        # this method should work on both instances and classes
        if type(plugin) is type:
            plugin = self.get_plugin_instance(plugin)

        if plugin not in self.active_plugins.values():
            return

        for widget in plugin.__cached_status_bar_widgets:
            self.workspace.main_window.statusBar().removeWidget(widget)
        for action in plugin.__cached_toolbar_actions:
            self.workspace._main_window._file_toolbar.remove(action)
        for action in plugin.__cached_menu_actions:
            self.workspace._main_window._plugin_menu.remove(action)

        try:
            plugin.teardown()

        except Exception:  # pylint: disable=broad-except
            log.warning(
                "Plugin %s errored during removal. The UI may be unstable.", plugin.get_display_name(), exc_info=True
            )

        for key in list(self.active_plugins.keys()):
            if self.active_plugins[key] is plugin:
                del self.active_plugins[key]

    #
    # Dispatchers
    #

    def _dispatch(self, func, sensitive, *args):
        for plugin in list(self.active_plugins.values()):
            custom = getattr(plugin, func.__name__)
            if custom.__func__ is not func:
                try:
                    res = custom(*args)
                except Exception as e:  # pylint: disable=broad-except
                    self._handle_error(plugin, func, sensitive, e)
                else:
                    yield res

    def _dispatch_with_plugin(self, func, sensitive, *args):
        for plugin_shortname, plugin in list(self.active_plugins.items()):
            custom = getattr(plugin, func.__name__)
            if custom.__func__ is not func:
                try:
                    res = custom(*args)
                except Exception as e:  # pylint: disable=broad-except
                    self._handle_error(plugin, func, sensitive, e)
                else:
                    yield (plugin_shortname, plugin), res

    def _dispatch_single(self, plugin, func, sensitive, *args):
        custom = getattr(plugin, func.__name__)
        try:
            return custom(*args)
        except Exception as e:  # pylint: disable=broad-except
            self._handle_error(plugin, func, sensitive, e)
            return None

    def _handle_error(self, plugin, func, sensitive, exc):
        self.workspace.log(f"Plugin {plugin.get_display_name()} errored during {func.__name__}")
        self.workspace.log(exc)
        if sensitive:
            self.workspace.log("Deactivating %s for error during sensitive operation" % plugin.get_display_name())
            self.deactivate_plugin(plugin)

    def color_insn(self, addr, selected) -> Optional["QColor"]:
        for res in self._dispatch(BasePlugin.color_insn, True, addr, selected):
            if res is not None:
                return res
        return None

    def color_block(self, addr) -> Optional["QColor"]:
        for res in self._dispatch(BasePlugin.color_block, True, addr):
            if res is not None:
                return res
        return None

    def color_func(self, func) -> Optional["QColor"]:
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

    def instrument_code_view(self, cview):
        for _ in self._dispatch(BasePlugin.instrument_code_view, False, cview):
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

    def handle_raise_view(self, view):
        for _ in self._dispatch(BasePlugin.handle_raise_view, False, view):
            pass

    def build_qblock_annotations(self, qblock: "QBlock"):
        for res in self._dispatch(BasePlugin.build_qblock_annotations, False, qblock):
            yield from res

    def build_context_menu_insn(self, insn):
        for res in self._dispatch(BasePlugin.build_context_menu_insn, False, insn):
            yield from res

    def build_context_menu_block(self, block):
        for res in self._dispatch(BasePlugin.build_context_menu_block, False, block):
            yield from res

    def build_context_menu_node(self, node):
        for res in self._dispatch(BasePlugin.build_context_menu_node, False, node):
            yield from res

    def build_context_menu_functions(self, funcs):
        for res in self._dispatch(BasePlugin.build_context_menu_functions, False, funcs):
            yield from res

    def get_func_column(self, idx):
        for plugin in self.active_plugins.values():
            if idx >= len(plugin.FUNC_COLUMNS):
                idx -= len(plugin.FUNC_COLUMNS)
            else:
                return plugin.FUNC_COLUMNS[idx]
        raise IndexError("Not enough columns")

    def count_func_columns(self):
        return sum(len(plugin.FUNC_COLUMNS) for plugin in self.active_plugins.values())

    def extract_func_column(self, func, idx):
        for plugin in self.active_plugins.values():
            if idx >= len(plugin.FUNC_COLUMNS):
                idx -= len(plugin.FUNC_COLUMNS)
            else:
                try:
                    return plugin.extract_func_column(func, idx)
                except Exception as e:  # pylint: disable=broad-except
                    # this should really be a "sensitive" operation but like
                    self.workspace.log(e)
                    self.workspace.log("PLEASE FIX YOUR PLUGIN AHHHHHHHHHHHHHHHHH")
                    return 0, ""
        raise IndexError("Not enough columns")

    def step_callback(self, simgr):
        for _ in self._dispatch(BasePlugin.step_callback, True, simgr):
            pass

    def handle_stack_var_renamed(self, func, offset, old_name, new_name):
        for res in self._dispatch(BasePlugin.handle_stack_var_renamed, False, func, offset, old_name, new_name):
            if res:
                return True
        return False

    def handle_stack_var_retyped(self, func, offset, old_type, new_type):
        for res in self._dispatch(BasePlugin.handle_stack_var_retyped, False, func, offset, old_type, new_type):
            if res:
                return True
        return False

    def handle_func_arg_renamed(self, func, offset, old_name, new_name):
        for res in self._dispatch(BasePlugin.handle_func_arg_renamed, False, func, offset, old_name, new_name):
            if res:
                return True
        return False

    def handle_func_arg_retyped(self, func, offset, old_type, new_type):
        for res in self._dispatch(BasePlugin.handle_func_arg_retyped, False, func, offset, old_type, new_type):
            if res:
                return True
        return False

    def handle_global_var_renamed(self, address, old_name, new_name):
        for res in self._dispatch(BasePlugin.handle_global_var_renamed, False, address, old_name, new_name):
            if res:
                return True
        return False

    def handle_global_var_retyped(self, address, old_type, new_type):
        for res in self._dispatch(BasePlugin.handle_global_var_retyped, False, address, old_type, new_type):
            if res:
                return True
        return False

    def handle_other_var_renamed(self, var, old_name, new_name):
        for res in self._dispatch(BasePlugin.handle_other_var_renamed, False, var, old_name, new_name):
            if res:
                return True
        return False

    def handle_other_var_retyped(self, var, old_type, new_type):
        for res in self._dispatch(BasePlugin.handle_other_var_retyped, False, var, old_type, new_type):
            if res:
                return True
        return False

    def handle_function_renamed(self, func, old_name, new_name):
        for res in self._dispatch(BasePlugin.handle_function_renamed, False, func, old_name, new_name):
            if res:
                return True
        return False

    def handle_function_retyped(self, func, old_type, new_type):
        for res in self._dispatch(BasePlugin.handle_global_var_retyped, False, func, old_type, new_type):
            if res:
                return True
        return False

    def handle_comment_changed(self, address, old_cmt, new_cmt, created: bool, decomp: bool):
        for res in self._dispatch(BasePlugin.handle_comment_changed, False, address, old_cmt, new_cmt, created, decomp):
            if res:
                return True
        return False

    def handle_struct_changed(self, old_struct, new_struct):
        for res in self._dispatch(BasePlugin.handle_struct_changed, False, old_struct, new_struct):
            if res:
                return True
        return False

    def decompile_callback(self, func):
        for _ in self._dispatch(BasePlugin.decompile_callback, False, func):
            pass

    def handle_project_initialization(self):
        for _ in self._dispatch(BasePlugin.handle_project_initialization, False):
            pass

    def handle_project_save(self, file_name: str):
        for _ in self._dispatch(BasePlugin.handle_project_save, False, file_name):
            pass

    def on_workspace_initialized(self, workspace):
        for _ in self._dispatch(BasePlugin.on_workspace_initialized, False, workspace):
            pass

    def angrdb_store_entries(self):
        entries = {}
        for (shortname, plugin), res in self._dispatch_with_plugin(BasePlugin.angrdb_store_entries, False):
            for result in res:
                if isinstance(result, tuple) and len(result) == 2:
                    key, value = result
                    key = shortname + "___" + key
                    entries[key] = value
        return entries

    def angrdb_load_entries(self, entries):
        plugin_name_to_plugin = self.active_plugins

        for key, value in entries.items():
            if "___" not in key:
                continue
            splitted = key.split("___")
            if len(splitted) != 2:
                continue
            plugin_shortname, key = splitted
            plugin = plugin_name_to_plugin.get(plugin_shortname, None)
            if plugin is None:
                continue
            # dispatch
            custom = getattr(plugin, "angrdb_load_entry")
            if custom is not BasePlugin.angrdb_load_entry:
                try:
                    custom(key, value)
                except Exception as ex:  # pylint: disable=broad-except
                    self._handle_error(plugin, BasePlugin.angrdb_load_entry, False, ex)

    def optimization_passes(self):
        for plugin in self.active_plugins.values():
            yield from plugin.OPTIMIZATION_PASSES
