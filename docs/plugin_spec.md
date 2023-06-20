# Plugin specification

angr management supports loading plugins that can extend and adapt the
functionality of angr management itself. In order to create an angr management
plugin, all that is needed is a directory containing two files: a `plugin.toml`
and a Python file where that plugin is implemented. For example, this is valid
plugin package directory layout:

```
example-plugin/
    example_plugin.py
    plugin.toml
```

Inside `example_plugin.py`, a super minimal plugin example looks like:

```py
import angrmanagement.plugins.BasePlugin

class ExamplePlugin(BasePlugin):
    pass
```

A valid `plugin.toml` that would allow this plugin to be loaded would look like
this:

```toml
[metadata]
version = 0

[package]
name = "example-plugin"
version = "1.0"

[plugin.example]
name = "Example Plugin"
version = "1.0"
entrypoints = ["example_plugin.py::ExamplePlugin"]
```

For more information what fields are available in a plugin.toml, se the
[plugin metadata specification](./plugin_metadata_spec.md).
