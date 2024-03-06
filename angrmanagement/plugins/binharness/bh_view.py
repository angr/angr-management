import logging

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QListView, QPushButton, QVBoxLayout

from .view import BaseView

log = logging.getLogger(name=__name__)


class BinharnessView(BaseView):
    environments_list: QListView

    def __init__(self, workspace, instance, default_docking_position):
        super().__init__("log", workspace, instance, default_docking_position)
        self.base_caption = "Binharness"
        self._init_widgets()
        self.reload()

    def closeEvent(self, event):
        super().closeEvent(event)

    def reload(self):
        for env_id in self.instance.bh_instance.environments:
            self.environments_list.addItem(str(env_id))

    @staticmethod
    def minimumSizeHint(*args, **kwargs):  # pylint: disable=unused-argument
        return QSize(50, 50)

    def _on_add_environment(self):
        log.debug("Adding environment")

    def _on_run_target(self):
        log.debug("Running target")

    def _init_widgets(self):
        layout = QVBoxLayout()
        self.environments_list = QListView()
        layout.add(self.environments_list)
        add_environment_button = QPushButton("Add Environment")
        add_environment_button.clicked.connect(self._on_add_environment)
        layout.add(add_environment_button)

        run_target_button = QPushButton("Run Target")
        run_target_button.clicked.connect(self._on_run_target)
        layout.add(run_target_button)

        self.setLayout(layout)
