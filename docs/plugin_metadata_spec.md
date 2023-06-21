Plugin Metadata Specification
=============================

Each plugin directory must have a plugin.toml file. A plugin metadata file has
three sections: `meta`, `package` and `plugins`. Each plugin.toml must contain
one meta section, but may contain Below are tables of keys for each sections.

## Meta section
| Key     | Type    | Required | Notes               |
| ------- | ------- | -------- | ------------------- |
| version | integer | yes      | Currently version 0 |


## Package section
| Key              | Type             | Required | Default | Notes     |
| ---------------- | ---------------- | -------- | ------- | --------- |
| name             | string           | yes      |         |           |
| version          | string           | yes      |         |           |
| platforms        | list[string]     | no       | ["any"] | See below |
| site_packages    | Optional[string] | no       | None    |           |
| authors          | list[string]     | no       | []      |           |
| description      | string           | no       | ""      |           |
| long-description | string           | no       | ""      |           |


### Values for `platforms`
angr management treats `"any"` as matching all platfoms. Otherwise, angr
management checks if Python's `sys.platform` starts with any of the listed
strings. See https://docs.python.org/3/library/sys.html#sys.platform to learn
more about the `sys.platform` value in Python.


## Plugins section
| Key                | Type                   | Required | Default               | Notes                                      |
| ------------------ | ---------------------- | -------- | --------------------- | ------------------------------------------ |
| name               | string                 | yes      |                       |                                            |
| entrypoint         | string                 | yes      |                       | Use file.py::ClassName syntax, like pytest |
| platforms          | Optional[list[string]] | no       | package.site-packages | overrides package default if configured    |
| description        | string                 | no       | ""                    |                                            |
| requires_workspace | bool                   | no       | false                 |                                            |
