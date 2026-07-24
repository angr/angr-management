MCP Server
==========

angr-management can run an embedded `Model Context Protocol <https://modelcontextprotocol.io>`_
(MCP) server that exposes the currently loaded binary to an AI agent. The agent can inspect the
program, decompile functions, and edit the analysis (rename functions and variables, change
types, add comments), and every change appears **live** in the angr-management GUI in front of
you -- the pseudocode view updates as the agent works.

Installation
------------
The MCP server needs a couple of extra packages. Install them with the ``mcp`` extra::

  pip install angr-management[mcp]

Starting the server
-------------------
From the GUI, use the **AI** menu:

* **Start MCP Server** -- starts the server (localhost only).
* **Stop MCP Server** -- stops it.
* **Copy MCP Server URL** -- copies the URL (and, if authentication is enabled, the bearer token)
  to the clipboard so you can hand it to an agent.

You can also start it from the command line when launching angr-management::

  angr-management --mcp target_binary
  angr-management --mcp --mcp-port 9000 target_binary

Configuration lives under **File -> Preferences -> MCP Server**, where you can set the port, make
the server start automatically on launch, and enable authentication.

Connecting an agent
-------------------
The server speaks streamable HTTP at ``http://localhost:8642/mcp`` by default. To register it with
Claude Code, for example::

  claude mcp add --transport http angr-management http://localhost:8642/mcp

Any MCP-capable client can connect the same way. Load a binary in angr-management first (or ask
the agent to guide you), then let the agent call the tools below.

Authentication
--------------
By default the server binds to localhost with no authentication, matching the trust model of the
existing angr-management daemon. If other processes on the machine are not trusted, enable
**Require a bearer token** in Preferences (or pass ``--mcp-auth`` / ``--mcp-auth-token TOKEN`` on
the command line). Clients must then send an ``Authorization: Bearer <token>`` header; **Copy MCP
Server URL** includes the token for convenience. If authentication is enabled without a token set,
angr-management generates one and saves it on first start.

Available tools
--------------
Tools that operate on the loaded binary are unprefixed. Reading tools access the analysis
directly; editing tools run on the GUI thread and refresh the relevant views.

**Inspection**

* ``get_project_info`` -- architecture, entry point, and analysis state.
* ``list_functions`` -- discovered functions, filterable by name pattern.
* ``get_function_info`` -- details for one function (by name or any address inside it).
* ``get_disassembly`` -- per-basic-block disassembly of a function.
* ``get_decompilation`` -- cached pseudocode for a function, exactly as shown in the GUI.
* ``get_xrefs`` -- cross-references to or from an address.
* ``get_strings`` -- strings recovered from the binary.
* ``get_imports`` / ``get_exports`` -- imported and exported symbols.
* ``get_callgraph`` -- the function call graph, optionally rooted at a function.

**Decompilation and navigation**

* ``decompile_function`` -- decompile a function via the same pipeline as the GUI. With
  ``focus=True`` (default) the pseudocode view opens on the function so you see the result; with
  ``focus=False`` it decompiles in the background without changing your view.
* ``jump_to`` -- navigate the disassembly view to an address.
* ``get_view_state`` -- report which view and functions you are currently looking at.

**Editing** (updates the GUI live)

* ``rename_function`` -- rename a function.
* ``rename_variable`` -- rename a variable in a decompiled function.
* ``set_variable_type`` -- change a variable's type.
* ``set_function_prototype`` -- set a function's signature and re-decompile it.
* ``set_comment`` -- add or clear a comment at an address.

Scratch analysis of other binaries
----------------------------------
The standalone ``angr`` MCP server is also mounted, with its tools exposed under the ``angr_``
prefix (``angr_load_binary``, ``angr_decompile_function``, and so on). These manage their own
separate project sessions and do **not** affect the GUI; use them only when the agent needs to
analyze a different binary on the side.
