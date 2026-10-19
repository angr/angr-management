"""
The menu bar and popup menus, drawn from angrmanagement.present.menus.

:class:`MenuBar` shows the captions of the top-level menus with their mnemonic letters underlined; F10 opens the
first menu, Alt+letter opens that menu, and a click opens the menu clicked. :class:`MenuPopup` is a menu on screen: Up
and Down move, Enter or the mnemonic letter chooses, Right opens a submenu or moves to the next top-level menu, Left
goes back, Escape closes. Each entry shows the shortcut that is bound on this terminal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import ModalScreen
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from angrmanagement.present.menus import Menu, MenuEntry, MenuSeparator

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual import events
    from textual.app import ComposeResult


def caption_text(caption: str, style: str = "") -> Text:
    """A caption with its mnemonic letter underlined and the ``&`` markers removed."""
    text = Text(style=style)
    idx = 0
    underlined = False
    while idx < len(caption):
        ch = caption[idx]
        if ch == "&" and idx + 1 < len(caption):
            if caption[idx + 1] == "&":
                text.append("&")
                idx += 2
                continue
            if not underlined:
                text.append(caption[idx + 1], style="underline")
                underlined = True
                idx += 2
                continue
        text.append(ch)
        idx += 1
    return text


class MenuPopup(ModalScreen[Any]):
    """
    A menu shown at a position on the screen.

    :param shortcut_text:   Turns an entry's Qt shortcut into the text shown; None hides shortcuts.
    :param on_leave:        Called with -1 or +1 when Left or Right asks for the neighbouring top-level menu.
    """

    DEFAULT_CSS = """
    MenuPopup {
        background: transparent;
        align: left top;
    }
    MenuPopup > OptionList {
        width: auto;
        height: auto;
        max-height: 90%;
        border: round $primary;
        background: $panel;
        padding: 0;
    }
    """

    BINDINGS: ClassVar = [
        Binding("escape", "close", "Close", show=False),
        Binding("left", "leave(-1)", "Previous menu", show=False),
        Binding("right", "leave(1)", "Next menu", show=False),
    ]

    def __init__(
        self,
        menu: Menu,
        offset: tuple[int, int],
        shortcut_text: Callable[[Any], str | None] | None = None,
        on_leave: Callable[[int], None] | None = None,
        parent_popup: MenuPopup | None = None,
    ) -> None:
        super().__init__()
        self.menu = menu
        self.offset_xy = offset
        self.shortcut_text = shortcut_text
        self.on_leave = on_leave
        self.parent_popup = parent_popup
        self.items = menu.items()
        self.option_list = OptionList(*self._options())

    def _entry_line(self, item: Any, width: int) -> Text:
        if isinstance(item, Menu):
            text = caption_text(item.caption)
            text.append(" " * max(1, width - len(text)) + "▶")
            return text
        mark = ""
        if isinstance(item, MenuEntry) and item.checkable:
            mark = "✓ " if item.checked else "  "
        text = Text(mark)
        text.append_text(caption_text(item.caption))
        shortcut = self.shortcut_text(item.shortcut) if (self.shortcut_text and item.shortcut) else None
        if shortcut:
            text.append(" " * max(2, width - len(text) - len(shortcut)))
            text.append(shortcut, style="dim")
        return text

    def _width(self) -> int:
        widest = 0
        for item in self.items:
            if isinstance(item, MenuEntry | Menu):
                length = len(item.text) + 2
                if isinstance(item, MenuEntry) and item.shortcut and self.shortcut_text:
                    length += len(self.shortcut_text(item.shortcut) or "") + 2
                widest = max(widest, length)
        return max(widest + 2, 16)

    def _options(self) -> list[Option | None]:
        width = self._width()
        options: list[Option | None] = []
        for idx, item in enumerate(self.items):
            if isinstance(item, MenuSeparator):
                options.append(None)
            elif isinstance(item, MenuEntry | Menu):
                enabled = item.enabled if isinstance(item, MenuEntry) else bool(item.items())
                options.append(Option(self._entry_line(item, width), id=str(idx), disabled=not enabled))
        # no separator at the very top or bottom
        while options and options[0] is None:
            options.pop(0)
        while options and options[-1] is None:
            options.pop()
        return options

    def compose(self) -> ComposeResult:
        yield self.option_list

    def on_mount(self) -> None:
        self.option_list.styles.offset = self.offset_xy
        self.option_list.focus()
        for idx, option in enumerate(self.option_list.options):
            if not option.disabled:
                self.option_list.highlighted = idx
                break

    def _item_of(self, option: Option) -> Any:
        return self.items[int(option.id or 0)]

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        self.choose(self._item_of(event.option))

    def choose(self, item: Any) -> None:
        if isinstance(item, Menu):
            self._open_submenu(item)
            return
        if isinstance(item, MenuEntry):
            self.close_all()
            self.app.call_later(item.trigger)

    def _open_submenu(self, menu: Menu) -> None:
        region = self.option_list.region
        highlighted = self.option_list.highlighted or 0
        offset = (region.right, region.y + highlighted)
        self.app.push_screen(MenuPopup(menu, offset, self.shortcut_text, parent_popup=self))

    def close_all(self) -> None:
        popup: MenuPopup | None = self
        while popup is not None:
            parent = popup.parent_popup
            popup.dismiss(None)
            popup = parent

    def action_close(self) -> None:
        self.dismiss(None)

    def action_leave(self, direction: int) -> None:
        if direction > 0:
            highlighted = self.option_list.highlighted
            if highlighted is not None:
                item = self._item_of(self.option_list.get_option_at_index(highlighted))
                if isinstance(item, Menu):
                    self._open_submenu(item)
                    return
        if self.parent_popup is not None:
            if direction < 0:
                self.dismiss(None)
            return
        if self.on_leave is not None:
            self.dismiss(None)
            self.on_leave(direction)

    def on_key(self, event: events.Key) -> None:
        if not event.character or not event.is_printable:
            return
        letter = event.character.lower()
        for idx, item in enumerate(self.items):
            if isinstance(item, MenuEntry | Menu) and item.mnemonic == letter:
                if isinstance(item, MenuEntry) and not item.enabled:
                    continue
                event.stop()
                self.choose(self.items[idx])
                return


class MenuBar(Horizontal):
    """The row of top-level menus."""

    DEFAULT_CSS = """
    MenuBar {
        height: 1;
        width: 100%;
        background: $panel;
    }
    MenuBar > .menu-title {
        width: auto;
        padding: 0 1;
    }
    MenuBar > .menu-title:hover {
        background: $primary 30%;
    }
    MenuBar > .menu-title.open {
        background: $primary;
        color: $text;
    }
    """

    def __init__(self, menus: list[Menu], shortcut_text: Callable[[Any], str | None] | None = None) -> None:
        super().__init__()
        self.menus = menus
        self.shortcut_text = shortcut_text
        self.open_index: int | None = None
        self.popup: MenuPopup | None = None

    def compose(self) -> ComposeResult:
        for idx, menu in enumerate(self.menus):
            yield Static(caption_text(menu.caption), classes="menu-title", id=f"menu-title-{idx}")

    def menu_names(self) -> list[str]:
        return [menu.text for menu in self.menus]

    def index_of(self, name: str) -> int | None:
        for idx, menu in enumerate(self.menus):
            if menu.text.lower() == name.lower() or (menu.mnemonic or "") == name.lower():
                return idx
        return None

    def open_menu(self, index: int) -> MenuPopup | None:
        """Open the menu at ``index`` under its caption."""
        if not 0 <= index < len(self.menus):
            return None
        self.close_menu()
        title = self.query_one(f"#menu-title-{index}", Static)
        offset = (title.region.x, title.region.y + 1)
        self.open_index = index
        title.add_class("open")
        popup = MenuPopup(self.menus[index], offset, self.shortcut_text, on_leave=self._leave)
        self.popup = popup
        self.app.push_screen(popup, callback=lambda _r, i=index: self._on_closed(i))
        return popup

    def close_menu(self) -> None:
        if self.popup is not None and self.popup.is_attached:
            self.popup.close_all()
        self.popup = None

    def _on_closed(self, index: int) -> None:
        for title in self.query(".menu-title"):
            title.remove_class("open")
        if self.open_index == index:
            self.open_index = None
            self.popup = None

    def _leave(self, direction: int) -> None:
        index = self.open_index if self.open_index is not None else 0
        self.app.call_later(self.open_menu, (index + direction) % len(self.menus))

    def on_click(self, event: events.Click) -> None:
        widget = event.widget
        if widget is not None and widget.id and widget.id.startswith("menu-title-"):
            event.stop()
            self.open_menu(int(widget.id.rsplit("-", 1)[1]))
