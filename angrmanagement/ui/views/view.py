from PySide2.QtWidgets import QFrame


class BaseView(QFrame):
    def __init__(self, category, workspace, default_docking_position, *args, **kwargs):

        super(BaseView, self).__init__(*args, **kwargs)

        self.workspace = workspace
        self.category = category
        self.default_docking_position = default_docking_position

        self.caption = None
