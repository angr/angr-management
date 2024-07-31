from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QSize, Signal
from PySide6.QtGui import QAction, QIcon, QMouseEvent
from PySide6.QtWidgets import QMenu, QStyle, QToolBar, QToolButton

from angrmanagement.config import IMG_LOCATION

from .toolbar import Toolbar

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.logic.disassembly import JumpHistory


class NavToolButton(QToolButton):
    """
    Widget to allow navigating a JumpHistory stack
    """

    triggered = Signal()
    triggeredFromMenu = Signal(int)

    def __init__(self, jump_history: JumpHistory, direction_forward: bool = False, parent=None) -> None:
        super().__init__(parent)
        self._dir_fwd = direction_forward
        self._jump_history = jump_history
        self.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        self._init_menu()

        if direction_forward:
            lbl = "Forward"
            ico = QIcon(os.path.join(IMG_LOCATION, "toolbar-forward.png"))
        else:
            lbl = "Back"
            ico = QIcon(os.path.join(IMG_LOCATION, "toolbar-previous.png"))

        a = QAction(ico, lbl, self)
        a.triggered.connect(self._on_button_activated)
        self.setDefaultAction(a)

    def _on_button_activated(self) -> None:
        self.triggered.emit()

    def _on_menu_action_activated(self, checked) -> None:  # pylint:disable=unused-argument
        pos = self.sender().data()
        self.triggeredFromMenu.emit(pos)

    def _init_menu(self) -> None:
        self._menu = QMenu()
        pos = self._jump_history.pos
        if pos < 0:
            pos += len(self._jump_history.history)

        actions = []
        for i, point in enumerate(self._jump_history.history):
            a = QAction(f"{i}: {point:x}", self)
            a.setData(i)
            a.setCheckable(True)
            a.setChecked(pos == i)
            a.triggered.connect(self._on_menu_action_activated)
            actions.append(a)

        actions.reverse()
        self._menu.addActions(actions)
        self.setMenu(self._menu)

    def mousePressEvent(self, e: QMouseEvent) -> None:
        self._init_menu()
        super().mousePressEvent(e)


class NavToolbar(Toolbar):
    """
    Navigation toolbar with forward, back, and menu-based navigation of a JumpHistory stack
    """

    def __init__(
        self,
        jump_history: JumpHistory,
        back_triggered: Callable[[], Any],
        forward_triggered: Callable[[], Any],
        point_triggered: Callable[[int], Any],
        small_icon: bool,
        window,
    ) -> None:
        super().__init__(window, "Navigation")
        self._jump_history = jump_history
        self._back_triggered = back_triggered
        self._forward_triggered = forward_triggered
        self._point_triggered = point_triggered
        self._small_icon = small_icon

    def qtoolbar(self) -> QToolBar:
        tb = QToolBar(self.window)
        if self._small_icon:
            sm_ico_pm = tb.style().pixelMetric(QStyle.PixelMetric.PM_SmallIconSize, None, tb)
            tb.setIconSize(QSize(sm_ico_pm, sm_ico_pm))

        back_btn = NavToolButton(self._jump_history, False, tb)
        back_btn.triggered.connect(self._back_triggered)
        back_btn.triggeredFromMenu.connect(self._point_triggered)
        tb.addWidget(back_btn)

        fwd_btn = NavToolButton(self._jump_history, True, tb)
        fwd_btn.triggered.connect(self._forward_triggered)
        fwd_btn.triggeredFromMenu.connect(self._point_triggered)
        tb.addWidget(fwd_btn)

        return tb
