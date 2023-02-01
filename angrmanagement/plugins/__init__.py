"""
All functions in this module return a list of mixed BasePlugin class and exception objects to indicate
either the success or failure of a load.

This file intentionally does not reuse angr.misc.autoimport since it has additional design goals (managing exceptions,
loading out-of-tree files).
"""
import logging

from .base_plugin import BasePlugin
from .load import (
    load_default_plugins,
    load_plugin_description,
    load_plugin_descriptions_from_dir,
    load_plugins_from_dir,
    load_plugins_from_file,
    load_plugins_from_module,
    load_plugins_from_package,
    load_plugins_from_vars,
)
from .plugin_description import PluginDescription
from .plugin_manager import PluginManager

log = logging.getLogger(__name__)


__all__ = [
    "BasePlugin",
    "PluginDescription",
    "PluginManager",
    "load_plugin_descriptions_from_dir",
    "load_plugin_description",
    "load_default_plugins",
    "load_plugins_from_dir",
    "load_plugins_from_package",
    "load_plugins_from_file",
    "load_plugins_from_module",
    "load_plugins_from_vars",
]
