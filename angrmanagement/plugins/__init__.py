"""
All functions in this module return a list of mixed BasePlugin class and exception objects to indicate
either the success or failure of a load.

This file intentionally does not reuse angr.misc.autoimport since it has additional design goals (managing exceptions,
loading out-of-tree files).
"""
import os
import logging
import importlib.util

l = logging.getLogger(__name__)

def load_default_plugins():
    return load_plugins_from_dir(os.path.dirname(os.path.abspath(__file__)), exclude=('base_plugin.py', 'plugin_manager.py'))

def load_plugins_from_dir(path, exclude=()):
    out = []
    try:
        dlist = os.listdir(path)
    except OSError:
        return []

    for filename in dlist:
        if filename in exclude or filename in ('__init__.py', '__pycache__'):
            continue
        fullname = os.path.join(path, filename)
        if os.path.isfile(fullname) and fullname.endswith('.py'):
            out += load_plugins_from_file(fullname)
        elif os.path.isfile(os.path.join(fullname, '__init__.py')):
            out += load_plugins_from_package(fullname)

    return out

def load_plugins_from_package(path):
    # this logic is a little multiplexed in the next function but like... whatever
    return load_plugins_from_file(os.path.join(path, '__init__.py'))

def load_plugins_from_file(path):
    basename = os.path.basename(path)
    if basename == '__init__.py':
        modname = os.path.basename(os.path.dirname(path))
        if modname.count('.') != 0:
            l.error("file %s cannot be loaded - weird name", path)
            return []
    else:
        modname = basename.split('.')[0]
        if basename.count('.') != 1:
            l.error("package %s cannot be loaded - weird name", path)
            return []

    # https://stackoverflow.com/questions/67631/how-to-import-a-module-given-the-full-path
    spec = importlib.util.spec_from_file_location("angrmanagement.plugins.%s" % modname, path)
    if spec is None:
        l.error("Not a python module: %s", path)
        return []
    try:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception as e:
        return [e]

    return load_plugins_from_module(mod)

def load_plugins_from_module(module):
    return load_plugins_from_vars(vars(module))

def load_plugins_from_vars(variables):
    out = []
    for _, cls in variables.items():
        if type(cls) is type and issubclass(cls, BasePlugin) and not hasattr(cls, '_%s__i_hold_this_abstraction_token' % cls.__name__):
            out.append(cls)
    return out

from .plugin_manager import PluginManager
from .base_plugin import BasePlugin
