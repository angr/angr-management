Quickstart
==========

Installation
------------

Portable, pre-built executable
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The easiest way to run angr-management is by grabbing a bundled release from the releases page: https://github.com/angr/angr-management/releases

Builds can be extracted and then run from anywhere.
Note that builds are currently unsigned.

From PyPI
^^^^^^^^^
To install angr-management, use pip::

  pip install angr-management

Alternatively, if you're using the `uv package manager <https://docs.astral.sh/uv/>`_, angr-management can be installed with::

  uv tool install angr-management

Once installed, angr-management can be run with the command :code:`angr-management`, or :code:`am`.

Development Install
^^^^^^^^^^^^^^^^^^^
See `angr-dev <https://github.com/angr/angr-dev>`_ for how to set up a development environment for the angr suite.
angr-management is included by default and checked out to :code:`angr-management` directory.
If you encounter dependency issues, re-running :code:`setup.sh` or :code:`setup.bat` from angr-dev will ensure all dependencies are installed.

angr-management can then be run with :code:`angr-management` or :code:`python start.py`.

**FLIRT signatures**: For now, please manually clone FLIRT signatures by running :code:`git clone --recurse-submodules https://github.com/angr/angr-management`, which will clone the :code:`flirt_signatures` submodule.

Views
-----
angr-management's window is partitioned into "views" of information about the binary, including:

* Functions - List of functions in the binary.
* Disassembly - Graph or linear disassembly of the binary's machine code.
* Pseudocode - Interactive function decompilation and source display (with the source viewer plugin).
* Hex - Hex-editor view of the binary's address space.
* Console - iPython terminal for working with the angr project and the angr-management workspace.
* Strings - Table of all strings found in the binary.
* Patches - Table of patches made to the binary.

Views can be opened from the main View menu and rearranged by click+dragging on the view title bar.

Command Palette
---------------
Ctrl+Shift+P opens the Command Palette, providing a quick menu of actions.

Goto Anything
-------------
Double-tapping the Shift key opens the *Goto Anything* dialog for a fuzzy matched search of objects to navigate to. Note: currently "anything" includes only functions.

Plugins
-------
angr-management includes a set of plugins that can optionally be enabled from the Plugins > Manage Plugins menu.

Plugins may be installed by placing a subdirectory under :code:`plugins`. The directory must contain an :code:`__init__.py` like that in :code:`TestPlugin`::

  from .test_plugin import TestPlugin
  PLUGIN_CLS_NAME = TestPlugin.__name__

This also allows you to import a plugin class from another package entirely. The plugin itself should inherit from :code:`BasePlugin`. Callbacks and events are a work in progress, so the API is subject to change. See :code:`TestPlugin` for an example of a multithreaded plugin sample.

Configuration
-------------

Configuration files locations vary by platform:

* Windows: :code:`~\AppData\Local\angr-management\config.toml`
* macOS: :code:`~/Library/Preferences/angr-management/config.toml`
* Linux: :code:`~/.config/angr-management/config.toml`
