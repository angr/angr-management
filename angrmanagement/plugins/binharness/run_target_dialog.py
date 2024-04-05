from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import binharness
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from angrmanagement.config import IMG_LOCATION

from .stream_view import StreamView

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace

    from .bhinstance import BhInstance

log = logging.getLogger(name=__name__)


class RunTargetDialog(QDialog):
    """
    Dialog that allows the user to run a target with a specific environment and executor.
    """

    bh_instance: BhInstance

    def __init__(self, workspace: Workspace, bh_instance: BhInstance):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.WindowTitleHint | Qt.WindowType.WindowCloseButtonHint)
        self.setWindowTitle("Run Target")
        # Icon
        angr_icon_location = os.path.join(IMG_LOCATION, "angr.png")
        self.setWindowIcon(QIcon(angr_icon_location))

        self.setMinimumWidth(400)

        self.bh_instance = bh_instance
        self.workspace = workspace
        self._init_widgets()

    def _init_widgets(self):
        # Select Environment
        self.env_combobox = QComboBox()
        self.env_combobox.addItems([env_id[0] for env_id in self.bh_instance.environments])

        # Select Executor
        self.executor_combobox = QComboBox()
        self.executor_combobox.addItems(["None"])

        # Run Button
        run_button = QPushButton("Run")
        run_button.clicked.connect(self._on_run_target)

        structure = QVBoxLayout()
        env_row = QHBoxLayout()
        env_row.addWidget(QLabel("Environment"))
        env_row.addWidget(self.env_combobox)
        exec_row = QHBoxLayout()
        exec_row.addWidget(QLabel("Executor"))
        exec_row.addWidget(self.executor_combobox)

        structure.addLayout(env_row)
        structure.addLayout(exec_row)
        structure.addWidget(run_button)

        layout = QHBoxLayout()
        layout.addLayout(structure)

        self.setLayout(layout)

    def _on_run_target(self):
        log.debug("Running target")

        # Setup and run target
        environment = [env for env in self.bh_instance.environments if env[0] == self.env_combobox.currentText()][0]
        source_target = self.bh_instance.targets[self.bh_instance.local_environment][0]
        if environment != source_target.environment:
            target = binharness.transport_target(source_target, environment[1])
        else:
            target = source_target

        if self.executor_combobox.currentText() == "None":
            executor = binharness.NullExecutor()

        process = executor.run_target(target)

        log.debug("Creating views")
        if self.executor_combobox.currentText() == "None":
            p_so = process.stdout
            stdout_view = StreamView(self.workspace, self.workspace.main_instance, "bottom", p_so, "stdout")
            log.debug("Adding stdout view")
            self.workspace.add_view(stdout_view)

        # Make stdout/stderr available to user

        log.debug("Target run")
        self.close()
