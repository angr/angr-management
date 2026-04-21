from __future__ import annotations

from typing import TYPE_CHECKING

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
from angr.calling_conventions import SimRegArg, SimStackArg
from PySide6.QtCore import QPoint, Qt, QTimer
from PySide6.QtGui import QFontMetrics, QGuiApplication, QTextOption
from PySide6.QtWidgets import QFrame, QPlainTextEdit, QVBoxLayout, QWidget

from angrmanagement.config import Conf

if TYPE_CHECKING:
    from angr.sim_type import SimTypeFunction

_MAX_WIDTH_PX = 900
_SHOW_DELAY_MS = 700


class QNodeTip(QFrame):
    """A tooltip-like popup that renders info about hovered node in the code view."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, Qt.WindowType.ToolTip | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setFrameShape(QFrame.Shape.Box)
        self.setStyleSheet(
            f"QFrame {{ border: 1px solid {Conf.palette_text.name()}; background-color: {Conf.palette_base.name()}; }}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(0)

        self._editor = QPlainTextEdit(self)
        self._editor.setReadOnly(True)
        self._editor.setFrameShape(QFrame.Shape.NoFrame)
        self._editor.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._editor.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._editor.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
        self._editor.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._editor.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        self._editor.setFont(Conf.code_font)
        self._editor.setStyleSheet(
            f"QPlainTextEdit {{ background-color: {Conf.palette_base.name()}; "
            f"color: {Conf.palette_text.name()}; border: 0; padding: 4px 6px; }}"
        )
        layout.addWidget(self._editor)

        self._current_node = None
        self._text: str = ""
        self._pending_pos: QPoint | None = None

        self._delay_timer = QTimer(self)
        self._delay_timer.setSingleShot(True)
        self._delay_timer.timeout.connect(self._on_timeout)

    @property
    def current_node(self):
        return self._current_node

    @current_node.setter
    def current_node(self, node) -> None:
        self._current_node = node
        if node is None:
            self.hide_tip()

    def show_tip(
        self,
        node,
        global_pos: QPoint,
    ) -> None:
        if node is None or self._current_node is node:
            return

        self.hide()
        self._delay_timer.stop()

        text = self._build_text(node)
        if text is None:
            self.hide_tip()
            return

        self._current_node = node
        self._text = text

        self._editor.setPlainText(text)
        self._editor.setFont(Conf.code_font)

        metrics = QFontMetrics(Conf.code_font)
        text_w = metrics.horizontalAdvance(text) + 24
        if text_w > _MAX_WIDTH_PX:
            text_w = _MAX_WIDTH_PX
            line_count = (metrics.horizontalAdvance(text) // (text_w - 24)) + 1
        else:
            line_count = 1
        text_h = metrics.height() * line_count + 16
        self._editor.setFixedSize(text_w, text_h)
        self.setFixedSize(text_w + 4, text_h + 4)

        self._pending_pos = global_pos
        self._delay_timer.start(_SHOW_DELAY_MS)

    def hide_tip(self) -> None:
        self._delay_timer.stop()
        self._pending_pos = None
        self._current_node = None
        self._text = ""
        self.hide()

    def text(self) -> str:
        return self._text

    def _build_text(self, node) -> str | None:
        if isinstance(node, CFunctionCall):
            return self._format_prototype(node)
        return None

    def _format_prototype(self, node: CFunctionCall) -> str | None:
        func = node.callee_func
        if func is None or func.prototype is None:
            return None

        proto: SimTypeFunction = func.prototype
        name = func.demangled_name or func.name or "sub"
        ret = proto.returnty.c_repr() if proto.returnty else "void"

        parts = []
        args = proto.args or ()
        arg_names = proto.arg_names or ()

        arg_locs = None
        cc = func.calling_convention
        if cc is not None and args:
            try:
                arg_locs = cc.arg_locs(proto)
            except Exception:
                arg_locs = None

        for i, arg_type in enumerate(args):
            arg_name = arg_names[i] if i < len(arg_names) and arg_names[i] else f"a{i}"
            arg_str = f"{arg_type.c_repr()} {arg_name}"
            if arg_locs is not None and i < len(arg_locs):
                loc = arg_locs[i]
                if isinstance(loc, SimRegArg):
                    arg_str += f" @ <{loc.reg_name}>"
                elif isinstance(loc, SimStackArg):
                    arg_str += f" @ <stack+{loc.stack_offset:#x}>"
            parts.append(arg_str)

        if proto.variadic:
            parts.append("...")

        return f"{ret} {name}({', '.join(parts)})"

    def _on_timeout(self) -> None:
        if self._pending_pos is not None:
            self._place_and_show(self._pending_pos)
            self._pending_pos = None

    def _place_and_show(self, global_pos: QPoint) -> None:
        target_x = global_pos.x() + 12
        target_y = global_pos.y() + 18
        screen = QGuiApplication.screenAt(global_pos)
        if screen is not None:
            avail = screen.availableGeometry()
            w = self.width()
            h = self.height()
            if target_x + w > avail.x() + avail.width():
                target_x = max(avail.x() + 2, avail.x() + avail.width() - w - 2)
            if target_y + h > avail.y() + avail.height():
                target_y = max(avail.y() + 2, avail.y() + avail.height() - h - 2)
        self.move(target_x, target_y)
        self.show()
