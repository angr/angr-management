import os
from angr.misc.autoimport import auto_import_modules, auto_import_packages
from .base_plugin import BasePlugin

def autoload_plugins(workspace):
    autoload_plugins_from_dir(workspace, os.path.dirname(os.path.abspath(__file__)))

def autoload_plugins_from_dir(workspace, path):
    for _, module in auto_import_modules('angrmanagement.plugins', path, ('base_plugin.py',)):
        autoload_plugins_from_module(workspace, module)
    for _, package in auto_import_packages('angrmanagement.plugins', path, scan_modules=False):
        autoload_plugins_from_module(workspace, package)

def autoload_plugins_from_file(workspace, path):
    with open(path) as fp:
        plugin_text = fp.read()

    g = {}
    exec(plugin_text, g)
    autoload_plugins_from_vars(workspace, g)

def autoload_plugins_from_module(workspace, module):
    autoload_plugins_from_vars(workspace, vars(module))

def autoload_plugins_from_vars(workspace, variables):
    for _, cls in variables.items():
        if type(cls) is type and issubclass(cls, BasePlugin) and not hasattr(cls, '_%s__i_hold_this_abstraction_token'):
            workspace._main_window.plugin_add(cls)
