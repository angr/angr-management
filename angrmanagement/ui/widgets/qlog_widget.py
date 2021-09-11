from PySide2.QtWidgets import QListView


class QLogWidget(QListView):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
