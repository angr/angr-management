import threading

import archr
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QMainWindow, QMessageBox, QPushButton, QVBoxLayout
from qtterm import TerminalWidget

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.views import BaseView
from angrmanagement.ui.views.interaction_view import (
    PlainTextProtocol,
    SavedInteraction,
)


class ConsoleView(BaseView):
    """
    ConsoleView
    """

    def __init__(self, workspace, *args, **kwargs):
        super().__init__("interaction console", workspace, *args, **kwargs)

        self.base_caption = "Interaction Console"
        self.workspace = workspace
        self.target = None
        self.conversations = {}
        self.terminal = TerminalWidget(command=None)
        self.analyzer = None
        self.interaction_context = None

        main_layout = QVBoxLayout()
        controls_layout = QHBoxLayout()

        connect_button = QPushButton()
        connect_button.setText("Connect")
        connect_button.clicked.connect(self.connect)
        controls_layout.addWidget(connect_button)

        terminal_window = QMainWindow()
        terminal_window.setWindowFlags(Qt.Widget)
        terminal_window.setCentralWidget(self.terminal)

        main_layout.addLayout(controls_layout)
        main_layout.addWidget(terminal_window)

        self.setLayout(main_layout)

    def connect(self):
        self.disconnect()

        img_name = self.workspace.main_instance.img_name
        if img_name is None:
            QMessageBox.critical(None, "Nothing to run", "The project was not loaded from a docker image")
            return

        self.target = archr.targets.DockerImageTarget(img_name, companion=True)
        self.target.build().start()

        self.analyzer = archr.analyzers.TCPDumpAnalyzer(self.target)

        self.interaction_context = self.analyzer.fire_context(timeout_exception=False)
        self.interaction_context.__enter__()  # pylint:disable=no-member

        threading.Thread(target=self._inotify_thread, daemon=True).start()

        self.workspace.extract_conversations = self.analyzer.extract_conversations

        self.terminal.execute(
            [
                "docker",
                "exec",
                "-it",
                self.target.companion_container.id,
                "bash",
            ]
        )

    def disconnect(self):
        if self.target:
            self.terminal.stop()
            self.target.__exit__()

    def _inotify_thread(self):
        inotify = self.target.run_companion_command(
            [
                "inotifywait",
                "--monitor",
                "--event",
                "modify",
                archr.analyzers.TCPDumpAnalyzer.pcap_path,
            ]
        )

        response = inotify.stderr.read(0x1000)
        if b"Watches established." not in response:
            raise Exception("Failed to setup TCPDump watcher!")

        while True:
            inotify.stdout.read(0x1000)
            conversations = self.analyzer.extract_conversations()
            for id_, conversation in conversations.items():
                if id_ not in self.conversations:
                    self._save_interaction(conversation)

            self.conversations = conversations

    def _save_interaction(self, conversation):
        target_port = self.target.tcp_ports[0]

        def direction(srcport, dstport):
            if srcport == target_port:
                return "out"
            if dstport == target_port:
                return "in"
            raise Exception("Unknown direction")

        log = [
            {
                "dir": direction(srcport, dstport),
                "data": payload,
            }
            for (srcport, dstport, payload) in conversation
        ]

        name = hex(hash(str(conversation)) & 0xFFFFFFFFFFFFFFFF)[2:].rjust(16, "0")

        self.workspace.main_instance.interactions.am_obj.append(SavedInteraction(name, PlainTextProtocol, log))
        self.workspace.main_instance.interactions.am_event()


class InteractionConsole(BasePlugin):
    """
    InteractionConsole Plugin
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.console_view = ConsoleView(self.workspace, "center")
        self.workspace.default_tabs += [self.console_view]
        self.workspace.add_view(self.console_view)

    def teardown(self):
        if self.console_view.target:
            self.console_view.target.__exit__()
