import unittest

import tomlkit
from marshmallow import ValidationError

from angrmanagement.plugins.plugin_description import (
    MetadataDescription,
    PackageDescription,
    PluginDescription,
    from_toml_string,
)


class TestPluginDescriptionLoading(unittest.TestCase):
    def test_metadta_section(self):
        test_data = "version = 0"
        MetadataDescription.Schema().load(tomlkit.parse(test_data))

    def test_metadata_section_invalid_version(self):
        test_data = "version = 1_000_000"
        with self.assertRaises(ValidationError):
            MetadataDescription.Schema().load(tomlkit.parse(test_data))

    def test_minimal_package(self):
        test_data = """
name = "example"
version = "1.0"
"""
        PackageDescription.Schema().load(tomlkit.parse(test_data))

    def test_minimal_plugin(self):
        test_data = """
name = "Example"
entrypoint = "example.py::ExamplePlugin"
"""
        PluginDescription.Schema().load(tomlkit.parse(test_data))

    def test_no_plugins(self):
        test_data = """
[metadata]
version = 0

[package]
name = "example"
version = "1.0"
"""
        from_toml_string(test_data)

    def test_minimal(self):
        test_data = """
[metadata]
version = 0

[package]
name = "example"
version = "1.0"

[plugin.example]
name = "Example"
entrypoint = "example.py::ExamplePlugin"
"""
        from_toml_string(test_data)

    def test_multiple(self):
        test_data = """
[metadata]
version = 0

[package]
name = "example"
version = "1.0"
platforms = ["any"]
site_packages = "site-packages"
authors = ["Example"]
description = "An example plugin package"
long_description = "An example plugin package for testing angr management"

[plugins.example1]
name = "Example 1"
entrypoint = "example.py::ExamplePlugin1"
platforms = ["linux"]
description = "An example plugin for testing angr management on linuz"
requires_workspace = false

[plugins.example2]
name = "Example 2"
entrypoint = "example.py::ExamplePlugin2"
platforms = ["win32", "cygwin"]
description = "An example plugin for testing angr management on windows"
requires_workspace = true
"""
        from_toml_string(test_data)


if __name__ == "__main__":
    unittest.main()
