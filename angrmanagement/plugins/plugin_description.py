from typing import List

import tomlkit
from tomlkit.items import AoT, Integer, String, Table


class PluginDescription:
    """
    Describes an angr management plugin. Can be generated from plugin.toml.
    """

    def __init__(self):
        # Metadata
        self.plugin_metadata_version: int = None

        # Plugin
        self.name: str = ""
        self.shortname: str = ""
        self.version: str = ""
        self.description: str = ""
        self.long_description: str = ""
        self.platforms: List[str] = []
        self.min_angr_vesion: str = ""
        self.author = ""
        self.entrypoints: List[str] = []
        self.require_workspace: bool = True
        self.has_url_actions: bool = False

        # file path
        self.plugin_file_path: str = ""

    @classmethod
    def load_single_plugin(cls, data: Table) -> "PluginDescription":
        desc = PluginDescription()

        desc.name = data.get("name", None)
        if not isinstance(desc.name, String):
            raise TypeError(f'"name" must be a String instance, not a {type(desc.name)}')
        if not desc.name:
            raise TypeError('"name" cannot be empty')

        desc.shortname = data.get("shortname", None)
        if not isinstance(desc.shortname, String):
            raise TypeError(f'"shortname" must be a String instance, not a {type(desc.shortname)}')
        if not desc.shortname:
            raise TypeError('"shortname" cannot be empty')

        desc.entrypoints = data.get("entrypoints", "")
        if not isinstance(desc.entrypoints, List) or not all(
            isinstance(entrypoint, String) for entrypoint in desc.entrypoints
        ):
            raise TypeError('"entrypoints" must be a List of String instances')
        if not desc.entrypoints:
            raise TypeError('"entrypoints" cannot be empty')

        # optional
        desc.version = data.get("version", "")
        desc.description = data.get("description", "")
        desc.long_description = data.get("long_description", "")
        desc.platforms = data.get("platforms", "")
        desc.min_angr_vesion = data.get("min_angr_version", "")
        desc.author = data.get("author", "")
        desc.require_workspace = data.get("require_workspace", True)
        desc.has_url_actions = data.get("has_url_actions", False)

        return desc

    @classmethod
    def from_toml(cls, file_path: str) -> List["PluginDescription"]:
        with open(file_path, encoding="utf-8") as f:
            data = tomlkit.load(f)

        # load metadata
        outer_desc = PluginDescription()
        if "meta" in data:
            if "plugin_metadata_version" in data["meta"]:
                if isinstance(data["meta"]["plugin_metadata_version"], Integer):
                    outer_desc.plugin_metadata_version = data["meta"]["plugin_metadata_version"].unwrap()

        if outer_desc.plugin_metadata_version is None:
            raise TypeError("Cannot find plugin_metadata_version")
        if outer_desc.plugin_metadata_version != 0:
            raise TypeError(f"Unsupported plugin metadata version {outer_desc.plugin_metadata_version}")

        descs = []
        # load plugin information
        if "plugins" in data and isinstance(data["plugins"], AoT):
            # multiple plugins to load!
            for plugin in data["plugins"]:
                desc = PluginDescription.load_single_plugin(plugin)
                desc.plugin_metadata_version = outer_desc.plugin_metadata_version
                desc.plugin_file_path = file_path
                descs.append(desc)
        elif "plugin" in data:
            desc = PluginDescription.load_single_plugin(data["plugin"])
            desc.plugin_metadata_version = outer_desc.plugin_metadata_version
            desc.plugin_file_path = file_path
            descs.append(desc)
        else:
            raise TypeError('Cannot find any "plugin" or "plugins" table.')

        return descs
