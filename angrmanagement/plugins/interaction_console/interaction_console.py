import threading

import archr
from PySide2.QtWidgets import QMainWindow, QMessageBox, QVBoxLayout
from PySide2.QtCore import Qt
from qtterm import TerminalWidget

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.views import BaseView
from angrmanagement.ui.views.interaction_view import (
    SavedInteraction,
    PlainTextProtocol,
)


class ConsoleView(BaseView):
    """
    ConsoleView
    """

    def __init__(self, target, *args, **kwargs):
        self.target = target

        super().__init__("interaction console", *args, **kwargs)
        self.caption = "Interaction Console"

        main_layout = QVBoxLayout()
        main = QMainWindow()
        terminal = TerminalWidget(
            command=[
                "docker",
                "exec",
                "-it",
                self.target.companion_container.id,
                "bash",
            ]
        )

        main.setWindowFlags(Qt.Widget)
        main.setCentralWidget(terminal)
        main_layout.addWidget(main)

        self.setLayout(main_layout)


class InteractionConsole(BasePlugin):
    """
    InteractionConsole Plugin
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.target = None
        self.conversations = {}

        img_name = self.workspace.instance.img_name
        if img_name is None:
            QMessageBox.critical(
                None, "Nothing to run", "The project was not loaded from a docker image"
            )
            return

        self.target = archr.targets.DockerImageTarget(img_name, companion=True)
        self.target.build().start()

        self.analyzer = archr.analyzers.TCPDumpAnalyzer(self.target)

        self.interaction_context = self.analyzer.fire_context(timeout_exception=False)
        self.interaction_context.__enter__()

        threading.Thread(target=self._inotify_thread, daemon=True).start()

        self.workspace.extract_conversations = self.analyzer.extract_conversations

        self.console_view = ConsoleView(self.target, self.workspace, "center")
        self.workspace.default_tabs += [self.console_view]
        self.workspace.add_view(
            self.console_view,
            self.console_view.caption,
            self.console_view.category,
        )

    def teardown(self):
        if self.target:
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

        self.workspace.instance.interactions.am_obj.append(
            SavedInteraction(name, PlainTextProtocol, log)
        )
        self.workspace.instance.interactions.am_event()
