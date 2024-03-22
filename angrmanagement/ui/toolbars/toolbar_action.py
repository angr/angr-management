from __future__ import annotations


class ToolbarAction:
    def __init__(self, icon, name: str, tooltip, triggered, checkable: bool = False, shortcut=None) -> None:
        self.icon = icon
        self.name = name
        self.tooltip = tooltip
        self.triggered = triggered
        self.checkable = checkable
        self.shortcut = shortcut

    def __hash__(self):
        return hash((ToolbarAction, self.name))

    def __eq__(self, other):
        return isinstance(other, ToolbarAction) and self.name == other.name


class ToolbarSplitter(ToolbarAction):
    def __init__(self) -> None:
        super().__init__(None, None, None, None)
