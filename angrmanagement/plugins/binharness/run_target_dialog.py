import logging
import os

import binharness
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from angrmanagement.config import IMG_LOCATION
from angrmanagement.ui.workspace import Workspace

from .bhinstance import BhInstance
from .fuzzer import FuzzerExecutor
from .fuzzer_view import FuzzerView
from .stream_view import StreamView

log = logging.getLogger(name=__name__)
log.setLevel(logging.DEBUG)


class RunTargetDialog(QDialog):
    """
    Dialog that shows application version, credits, etc.
    """

    bh_instance: BhInstance

    def __init__(self, workspace: Workspace, bh_instance: BhInstance):
        super().__init__()
        self.setWindowFlags(Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.setWindowTitle("Run Target")
        # mdiIcon
        angr_icon_location = os.path.join(IMG_LOCATION, "angr.png")
        self.setWindowIcon(QIcon(angr_icon_location))

        self.setMinimumWidth(400)

        self.bh_instance = bh_instance
        self.workspace = workspace
        log.debug("RunTargetDialog initializing")
        try:
            self._init_widgets()
        except Exception as e:
            log.exception(e)
        log.debug("RunTargetDialog initialized")

    def _init_widgets(self):
        # Select Environment
        self.env_combobox = QComboBox()
        self.env_combobox.addItems([env_id[0] for env_id in self.bh_instance.environments])

        # Select Executor
        self.executor_combobox = QComboBox()
        self.executor_combobox.addItems(["None"])
        self.executor_combobox.addItems(["Fuzzer"])

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
            executor = binharness.PtyExecutor()  # TODO: make configurable, transport if needed, etc
        if self.executor_combobox.currentText() == "Fuzzer":
            log.debug("Using experimental fuzzer")
            executor = FuzzerExecutor()
            log.debug("Installing fuzzer")
            executor.install(target.environment)
            log.debug("Fuzzer installed")

        process = executor.run_target(target)

        log.debug("Creating views")
        if self.executor_combobox.currentText() == "None":
            p_so = process.stdout
            stdout_view = StreamView(self.workspace, self.workspace.main_instance, "bottom", p_so, "stdout")
            log.debug("Adding stdout view")
            self.workspace.add_view(stdout_view)
        if self.executor_combobox.currentText() == "Fuzzer":
            fuzzer_view = FuzzerView(self.workspace, self.workspace.main_instance, "center", executor)
            self.workspace.add_view(fuzzer_view)

        # Make stdout/stderr available to user

        log.debug("Target run")
        self.close()
