"""
Managing plugins without a toolkit: the Installed Plugins dialog's list, turning plugins on and off, and adding
plugins from a plugin.toml file. The Qt LoadPlugins dialog and the terminal's Manage Plugins screen both use it.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from angrmanagement.plugins import load_plugin_description

if TYPE_CHECKING:
    from collections.abc import Mapping

    from angrmanagement.plugins import PluginDescription, PluginManager

#: what the Load Plugin button asks for
PLUGIN_FILE_QUESTION = ("Open a plugin description file (plugin.toml)", "", "Toml files (*.toml)")


def plugin_rows(pm: PluginManager) -> list[tuple[PluginDescription, bool]]:
    """Each known plugin and whether it is active, in the order the plugin manager loaded them."""
    return [(desc, pm.get_plugin_instance_by_name(desc.shortname) is not None) for desc in pm.loaded_plugins.values()]


def apply_plugin_choices(pm: PluginManager, active: Mapping[str, bool]) -> None:
    """Activate the plugins checked and deactivate those unchecked (by short name), then remember the choice."""
    for shortname, checked in active.items():
        running = pm.get_plugin_instance_by_name(shortname) is not None
        if checked and not running:
            pm.activate_plugin_by_name(shortname)
        elif not checked and running:
            pm.deactivate_plugin_by_name(shortname)
    pm.save_enabled_plugins_to_config()


def add_plugins_from_file(pm: PluginManager, file_path: str) -> list[PluginDescription]:
    """Read the plugin descriptions of a plugin.toml and add them to the known plugins; none if it has none."""
    plugins = load_plugin_description(str(Path(file_path).parent))
    for plugin in plugins:
        pm.loaded_plugins[plugin.shortname] = plugin
    return plugins


__all__ = ["PLUGIN_FILE_QUESTION", "add_plugins_from_file", "apply_plugin_choices", "plugin_rows"]
