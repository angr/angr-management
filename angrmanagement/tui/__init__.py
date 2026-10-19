"""
The terminal (Textual) frontend of angr management.

``am-tui`` starts it (angrmanagement.tui.__main__); :class:`angrmanagement.tui.app.AmApp` is the app. It draws the
presenters of angrmanagement.present, as the Qt frontend does, and imports nothing from PySide6.
"""

from __future__ import annotations
