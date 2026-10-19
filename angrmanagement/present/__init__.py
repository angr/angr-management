"""
What a view shows and does, without a toolkit.

The modules here hold the state and the actions behind the views, the menus, the key bindings and the colours. Both
frontends draw from them: the Qt one in angrmanagement.ui and the terminal one in angrmanagement.tui. Nothing in this
package imports PySide6 or Textual.
"""

from __future__ import annotations
