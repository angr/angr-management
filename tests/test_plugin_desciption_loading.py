import unittest

import tomlkit

from angrmanagement.plugins.plugin_description import (
    PackageDescription,
    PluginDescription,
    from_toml_string,
    MetadataDescription,
    MetadataDescription,
    MetadataDescription,
)


class TestPluginDescriptionLoading(unittest.TestCase):
    def test_metadta_section(self):
        test_data = "version = 0"
        MetadataDescription.Schema().load(tomlkit.parse(test_data))

    def test_metadata_section_invalid_version(self):
        test_data = "version = 1_000_000"
        with self.assertRaises(Exception):
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

    def test_minimal(self):
        test_data = """
[metadata]
version = 0

[package]
name = "example"
version = "1.0"

[plugin.example]
name = "Example"
version = "1.0"
entrypoints = ["example.py::ExamplePlugin"]
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
site_pacakges = "site-packages"
authors = ["Example"]
description = "An example plugin package"
long-description = "An example plugin package for testing angr management"

[plugin.example1]
name = "Example 1"
entrypoints = ["example.py::ExamplePlugin1"]
platforms = ["linux"]
description = "An example plugin for testing angr management on linuz"
requires-workspace = false

[plugin.example2]
name = "Example 2"
entrypoints = ["example.py::ExamplePlugin2"]
platforms = ["win32", "cygwin"]
description = "An example plugin for testing angr management on windows"
requires-workspace = true
"""
        from_toml_string(test_data)


if __name__ == "__main__":
    unittest.main()
