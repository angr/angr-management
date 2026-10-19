The terminal frontend
=====================

``am-tui`` runs angr-management in a terminal. It shows the same views, menus, dialogs and plugins as the Qt
window, over the same presenters, so a change made in one is the change made in the other::

  pip install angr-management[tui]   # the tui extra adds textual-image, for tier 3
  am-tui target_binary
  am-tui --with-daemon --mcp target_binary

Without a binary it starts on the Welcome screen. F10 opens the menu bar and the command palette is on
Ctrl+Shift+P (Ctrl+P on a terminal that cannot report it).

Terminal tiers
--------------
What the app can do depends on the terminal. It asks the terminal before it starts and picks a tier; **Help ->
Terminal Capabilities** says what it found. Set ``AM_TUI_TIER`` to 0, 1, 2 or 3 before starting to use another one.

* **Tier 0**, any terminal: every feature. A Qt shortcut the terminal cannot report (Ctrl+Shift+T, Ctrl+Tab and
  so on) is bound to another chord, and the menus show the chord that works (Alt+T, Ctrl+PgDown). The minimap is
  drawn in braille.
* **Tier 1**, true colour: addresses in the disassembly and functions in the pseudocode are links (OSC 8) to
  ``angr://?action=jumpto&addr=...``. On every tier, copying asks the terminal to set the system clipboard (OSC 52)
  and keeps a copy for pasting inside the app.
* **Tier 2**, the kitty keyboard protocol: every Qt shortcut as the Qt window binds it, double Shift included.
* **Tier 3**, graphics (kitty or Sixel, through textual-image): the minimap, the feature map, the trace map, the
  About logo and the Save image preview are pictures. **View -> Graph Picture** shows the graph as a picture; when
  PySide6 is installed Qt draws it offscreen with a real font ("picture mode"). Nothing needs PySide6.

kitty
-----
In kitty, an ``angr://`` URL that arrives through the daemon focuses the window running am-tui (kitty's remote
control has to be allowed); elsewhere the terminal bell rings. A job that ran for ten seconds or more raises a desktop
notification (OSC 99) when it ends while the window is not focused.

Opening a view in a window of its own, attached to the same session through the daemon, is future work: the daemon
passes URL actions between processes, and a second process cannot show the first one's workspace.

Plugins
-------
The bundled plugins work in both frontends. A plugin of your own does too when its entry point (the file
``plugin.toml`` names) imports no toolkit at module level: import PySide6 or your Qt widgets inside a branch on
``angrmanagement.plugins.base_plugin.qt_frontend()``, and use the neutral hooks and ``GlobalInfo.ui_services`` for
what both frontends show and ask.

Configuration entries hold frontend-neutral values: ``Conf.entry(name).value`` is a ``Color`` where it used to be a
``QColor`` and a ``FontSpec`` where it was a ``QFont``, and ``Conf.entry(name).changed`` emits the same. To get the
value as the running frontend uses it, listen with ``Conf.connect(name, fn, init)``, which gives a Qt plugin the
``QColor`` or ``QFont``.

Layout
------
The sizes of the side and bottom areas, the tabs open in each area and the active ones are saved in the
configuration (``tui_layout``) when the app exits with a binary loaded, and opened again with the next binary.
