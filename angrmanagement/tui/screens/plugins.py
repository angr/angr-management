"""
The terminal's Manage Plugins screen, the Qt LoadPlugins dialog ("Installed Plugins"): every known plugin with a check
box for whether it is active, and Load Plugin to add the plugins of a plugin.toml. OK turns them on and off.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, SelectionList

from angrmanagement.present.plugins import (
    PLUGIN_FILE_QUESTION,
    add_plugins_from_file,
    apply_plugin_choices,
    plugin_rows,
)

from . import FilePickerScreen, MessageScreen, dialog_css

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from angrmanagement.plugins import PluginManager


class PluginsScreen(ModalScreen["bool | None"]):
    """Installed Plugins: dismisses with True once the choices are applied, None if cancelled."""

    DEFAULT_CSS = (
        dialog_css("PluginsScreen")
        + """
PluginsScreen > Vertical { width: 80; height: 70%; }
PluginsScreen SelectionList { height: 1fr; }
"""
    )
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, plugin_manager: PluginManager) -> None:
        super().__init__()
        self.title_text = "Installed Plugins"
        self.pm = plugin_manager

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            yield Button("Load Plugin", id="load")
            yield Label("Plugins", classes="group")
            yield SelectionList[str](
                *((desc.name, desc.shortname, active) for desc, active in plugin_rows(self.pm)), id="plugins"
            )
            with Horizontal(classes="buttons"):
                yield Button("OK", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        for widget in self.query("#plugins"):
            widget.focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "ok":
            self.action_accept()
        elif event.button.id == "load":
            self._load()
        else:
            self.action_cancel()

    def _load(self) -> None:
        caption, directory, name_filter = PLUGIN_FILE_QUESTION

        def picked(paths: Any) -> None:
            if not paths:
                return
            plugins = add_plugins_from_file(self.pm, paths[0])
            if not plugins:
                self.app.push_screen(MessageScreen("warning", "Error", "File contained no plugin descriptions"))
                return
            selections = self.query_one("#plugins", SelectionList)
            for plugin in plugins:
                selections.add_option((plugin.name, plugin.shortname, False))

        self.app.push_screen(FilePickerScreen(caption, directory, name_filter, "open"), picked)

    def action_accept(self) -> None:
        selections = self.query_one("#plugins", SelectionList)
        selected = set(selections.selected)
        apply_plugin_choices(self.pm, {shortname: shortname in selected for shortname in self.pm.loaded_plugins})
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(None)


__all__ = ["PluginsScreen"]
