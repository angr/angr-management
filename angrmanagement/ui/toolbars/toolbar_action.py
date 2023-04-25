class ToolbarAction:
    def __init__(self, icon, name, tooltip, triggered, checkable=False, shortcut=None):
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
    def __init__(self):
        super().__init__(None, None, None, None)
