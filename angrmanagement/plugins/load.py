import importlib
import logging
import os
import sys
from typing import List, Tuple

from .base_plugin import BasePlugin
from .plugin_description import PluginDescription

log = logging.getLogger(__name__)


def load_plugin_descriptions_from_dir(path: str) -> List[Tuple[str, PluginDescription]]:
    try:
        dlist = os.listdir(path)
    except OSError:
        return []

    plugins = []
    for d in dlist:
        descs = load_plugin_description(os.path.join(path, d))
        for desc in descs:
            plugins.append((d, desc))
    return plugins


def load_plugin_description(path: str) -> List[PluginDescription]:
    try:
        flist = os.listdir(path)
    except OSError:
        return []

    if "plugin.toml" in flist:
        fpath = os.path.join(path, "plugin.toml")
        if os.path.isfile(fpath):
            return PluginDescription.from_toml(fpath)
    return []


def load_default_plugins():
    return load_plugins_from_dir(
        os.path.dirname(os.path.abspath(__file__)),
        exclude=("base_plugin.py", "plugin_manager.py", "plugin_description.py"),
    )


def load_plugins_from_dir(path, exclude=()):
    # hack.
    if not exclude and path == os.path.dirname(__file__):
        exclude = ("base_plugin.py", "plugin_manager.py")

    out = []
    try:
        dlist = os.listdir(path)
    except OSError:
        return []

    for filename in dlist:
        if filename in exclude or filename in ("__init__.py", "__pycache__"):
            continue
        fullname = os.path.join(path, filename)
        if os.path.isfile(fullname) and fullname.endswith(".py"):
            out += load_plugins_from_file(fullname)
        elif os.path.isfile(os.path.join(fullname, "__init__.py")):
            out += load_plugins_from_package(fullname)

    return out


def load_plugins_from_package(path):
    # this logic is a little multiplexed in the next function but like... whatever
    return load_plugins_from_file(os.path.join(path, "__init__.py"))


def load_plugins_from_file(path):
    basename = os.path.basename(path)
    if basename == "__init__.py":
        modbasename = os.path.basename(os.path.dirname(path))
        if modbasename.count(".") != 0:
            log.error("file %s cannot be loaded - weird name", path)
            return []
    else:
        if os.path.isfile(path):
            modbasename = os.path.basename(os.path.dirname(path))
            modbasename += "." + basename.split(".")[0]
            if modbasename.count(".") != 1:
                log.error("package %s cannot be loaded - weird name", path)
                return []
        else:
            # directory
            modbasename = basename.split(".")[0]
            path = os.path.join(path, "__init__.py")
            if basename.count(".") != 0:
                log.error("package %s cannot be loaded - weird name", path)
                return []
    modname = "angrmanagement.plugins.%s" % modbasename

    # https://stackoverflow.com/questions/67631/how-to-import-a-module-given-the-full-path
    spec = importlib.util.spec_from_file_location(modname, path, submodule_search_locations=[])
    if spec is None:
        log.error("Not a python module: %s", path)
        return []
    try:
        mod = importlib.util.module_from_spec(spec)
        sys.modules[modname] = mod
        spec.loader.exec_module(mod)
    except Exception as e:
        return [e]

    return load_plugins_from_module(mod)


def load_plugins_from_module(module):
    return load_plugins_from_vars(vars(module))


def load_plugins_from_vars(variables):
    out = []
    for _, cls in variables.items():
        if (
            type(cls) is type
            and issubclass(cls, BasePlugin)
            and not hasattr(cls, "_%s__i_hold_this_abstraction_token" % cls.__name__)
        ):
            out.append(cls)
    return out
