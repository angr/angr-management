Plugins
=======

Writing plugins
^^^^^^^^^^^^^^^

angr management has a very flexible plugin framework. A plugin is a Python file
containing a subclass of ``angrmanagement.plugins.BasePlugin``. Plugin files
will be automatically loaded from the ``plugins`` module of angr management, and
also from ``~/.local/share/angr-management/plugins``. These paths are
configurable through the program configuration, but at the time of writing, this
is not exposed in the UI.

The best way to see the tools you can use while building a plugin is to read the
`plugin base class source code
<https://github.com/angr/angr-management/blob/master/angrmanagement/plugins/base_plugin.py>`_.
Any method or attribute can be overridden from a base class and will be
automatically called on relevant events.
