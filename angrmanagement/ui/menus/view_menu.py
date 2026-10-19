from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.present.shell import build_new_view_menu, build_view_menu

from .menu import Menu, MenuEntry, MenuSeparator

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow
    from angrmanagement.ui.toolbars.toolbar import Toolbar


class NewViewMenu(Menu):
    """
    Sub-menu to construct new Views, from :func:`~angrmanagement.present.shell.build_new_view_menu`.
    """

    def __init__(self, main_window: MainWindow) -> None:
        built = build_new_view_menu(main_window)
        super().__init__(built.caption, built.entries, parent=main_window)


class ToolbarMenuEntry(MenuEntry):
    """
    Menu item to control toolbar visibility.
    """

    def __init__(self, toolbar_cls: type[Toolbar], main_window: MainWindow) -> None:
        tm = main_window.toolbar_manager
        super().__init__(tm.get_name_for_toolbar_class(toolbar_cls), self.on_toggle, checkable=True)
        self.main_window = main_window
        self.toolbar_cls = toolbar_cls

    @property
    def is_visibile(self) -> bool:
        qtb = self.main_window.toolbar_manager.active.get(self.toolbar_cls, None)
        return qtb is not None and qtb.qtoolbar().isVisible()

    def on_toggle(self) -> None:
        self.main_window.toolbar_manager.set_toolbar_visible_by_class(self.toolbar_cls, not self.is_visibile)

    def update_checked(self) -> None:
        self.checked = self.is_visibile


class ToolbarMenu(Menu):
    """
    Sub-menu to control toolbar visibility.
    """

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__("&Toolbars", parent=main_window)
        tm = main_window.toolbar_manager
        self.entries.extend([MenuEntry("Show all", tm.show_all), MenuEntry("Hide all", tm.hide_all), MenuSeparator()])
        for tb_cls in tm.all_toolbars:
            self.entries.append(ToolbarMenuEntry(tb_cls, main_window))
        self.qmenu().aboutToShow.connect(self.update_checked_entries)

    def update_checked_entries(self) -> None:
        for e in self.entries:
            if isinstance(e, ToolbarMenuEntry):
                e.update_checked()


class ViewMenu(Menu):
    """
    Main View menu, from :func:`~angrmanagement.present.shell.build_view_menu`, with the Qt toolbars submenu.
    """

    def __init__(self, main_window: MainWindow) -> None:
        built = build_view_menu(main_window, [ToolbarMenu(main_window)], new_menu=NewViewMenu(main_window))
        super().__init__(built.caption, built.entries, parent=main_window)
