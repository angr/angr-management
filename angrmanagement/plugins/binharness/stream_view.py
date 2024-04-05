from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, QTimer
from PySide6.QtWidgets import QTextEdit, QVBoxLayout

from angrmanagement.ui.views import InstanceView

if TYPE_CHECKING:
    from binharness import IO

log = logging.getLogger(name=__name__)


class StreamWidget(QTextEdit):
    """StreamWidget displays a stream of bytes as text."""

    def __init__(self, stream: IO[bytes]):
        super().__init__()
        self.stream = stream
        self.stream.set_blocking(False)
        self.buffer = b""
        self.setReadOnly(True)
        self.setText("")

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.reload)
        self.timer.start(100)

    def reload(self):
        new_data = self.stream.read(1024)
        if new_data:
            self.buffer += new_data
            self.setText(self.buffer.decode("utf-8"))


class StreamView(InstanceView):
    """StreamView displays a stream of bytes as text."""

    _stream: IO[bytes]
    _buffer: str

    _text_edit: QTextEdit

    def __init__(self, workspace, instance, default_docking_position, stream: IO[bytes], caption: str):
        super().__init__("log", workspace, default_docking_position, instance)

        self.base_caption = caption

        log.debug("StreamView initializing")
        self._text_edit = StreamWidget(stream)

        hlayout = QVBoxLayout()
        hlayout.addWidget(self._text_edit)
        hlayout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(hlayout)
        log.debug("StreamView initialized")

    @staticmethod
    def minimumSizeHint(*args, **kwargs):  # pylint: disable=unused-argument
        return QSize(50, 0)
