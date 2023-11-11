import pathlib
from dataclasses import field
from typing import ClassVar, Dict, List, Optional, Type

import marshmallow.validate
import tomlkit
from marshmallow import Schema
from marshmallow_dataclass import dataclass


@dataclass
class MetadataDescription:
    Schema: ClassVar[Type[Schema]] = Schema  # placate mypy

    version: int = field(metadata={"validate": marshmallow.validate.OneOf([0])})


@dataclass
class PackageDescription:
    """
    Describes a plugin package.
    """

    Schema: ClassVar[Type[Schema]] = Schema  # placate mypy

    name: str = field()
    version: str = field()
    platforms: List[str] = field(default_factory=lambda: ["any"])
    site_packages: Optional[str] = field(default=None)
    authors: List[str] = field(default_factory=list)
    description: str = field(default="")
    long_description: str = field(default="")


@dataclass
class PluginDescription:
    """
    Describes an angr management plugin. Can be generated from plugin.toml.
    """

    Schema: ClassVar[Type[Schema]] = Schema  # placate mypy

    name: str = field()
    entrypoint: str = field()
    platforms: Optional[List[str]] = field(default=None)
    description: str = field(default="")
    requires_workspace: bool = field(default=False)


@dataclass
class PluginConfigFileDescription:
    """
    Describes a plugin config file.
    """

    Schema: ClassVar[Type[Schema]] = Schema  # placate mypy

    metadata: MetadataDescription = field()
    package: PackageDescription = field()
    plugins: Dict[str, PluginDescription] = field(default_factory=dict)


def from_toml_string(toml_string: str) -> PluginConfigFileDescription:
    """
    Load a plugin config file from a TOML string.
    """
    return PluginConfigFileDescription.Schema().load(tomlkit.parse(toml_string))


def from_toml_file(toml_file: pathlib.Path) -> PluginConfigFileDescription:
    """
    Load a plugin config file from a TOML file.
    """
    with open(toml_file) as f:
        return from_toml_string(f.read())
