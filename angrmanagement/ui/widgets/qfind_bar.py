from __future__ import annotations

import re
from typing import TYPE_CHECKING

from PySide6.QtCore import QEvent, Qt, Signal
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QCheckBox, QComboBox, QHBoxLayout, QLabel, QLineEdit, QToolButton, QWidget

from angrmanagement.data.search import loose_whitespace_regex
from angrmanagement.ui.icons import icon

if TYPE_CHECKING:
    from collections.abc import Sequence

    from PySide6.QtGui import QKeyEvent


class QFindBar(QWidget):
    """
    An incremental find bar: query box, previous/next, case and regex toggles, a match counter and
    a close button. It owns no search logic; the host connects to :attr:`query_changed`,
    :attr:`find_next` and :attr:`find_previous` and calls :meth:`set_match_status` back. A host may
    pass ``modes`` to add a mode selector (e.g. hex pattern vs. text); mode changes are reported
    through :attr:`query_changed` as well.
    """

    query_changed = Signal()
    find_next = Signal()
    find_previous = Signal()
    closed = Signal()

    def __init__(self, parent: QWidget | None = None, modes: Sequence[str] | None = None) -> None:
        super().__init__(parent)
        self._status_label: QLabel
        self._query_box: QLineEdit
        self._modes = list(modes) if modes else None
        self._mode_combo: QComboBox | None = None
        self._init_widgets()
        self.hide()

    #
    # Properties
    #

    @property
    def query(self) -> str:
        return self._query_box.text()

    @property
    def case_sensitive(self) -> bool:
        return self._case_box.isChecked()

    @property
    def use_regex(self) -> bool:
        return self._regex_box.isChecked()

    @property
    def mode(self) -> str | None:
        return self._mode_combo.currentText() if self._mode_combo is not None else None

    #
    # Public methods
    #

    def compile_query(self, loose_whitespace: bool = False) -> re.Pattern | None:
        """
        Compile the current query into a regex, or return None if it is empty or malformed. With
        ``loose_whitespace``, a literal query tolerates whitespace differences around punctuation.
        """
        text = self.query
        if not text:
            self.set_error(False)
            return None
        flags = 0 if self.case_sensitive else re.IGNORECASE
        if self.use_regex:
            source = text
        elif loose_whitespace:
            source = loose_whitespace_regex(text)
        else:
            source = re.escape(text)
        try:
            pattern = re.compile(source, flags)
        except re.error:
            self.set_error(True)
            return None
        self.set_error(False)
        return pattern

    def activate(self, initial_text: str | None = None) -> None:
        """
        Show the bar and put the keyboard focus in the query box.
        """
        if initial_text:
            self._query_box.setText(initial_text)
        self.show()
        self._query_box.setFocus()
        self._query_box.selectAll()

    def set_match_status(self, current: int, total: int, capped: bool = False) -> None:
        """
        Update the match counter. ``capped`` marks that matching stopped at ``total`` (the
        configured limit) with more hits available, shown as "N+".
        """
        if not self.query:
            self._status_label.setText("")
        elif total == 0:
            self._status_label.setText("No matches")
        else:
            self._status_label.setText(f"{current + 1} of {total}{'+' if capped else ''}")

    def set_text_options_visible(self, visible: bool) -> None:
        """
        Show or hide the case/regex toggles, for modes where they do not apply.
        """
        self._case_box.setVisible(visible)
        self._regex_box.setVisible(visible)

    def set_error(self, is_error: bool) -> None:
        palette = self._query_box.palette()
        palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.red if is_error else self._default_text_color)
        self._query_box.setPalette(palette)
        self._query_box.setToolTip("Invalid regular expression" if is_error else "")

    def close_bar(self) -> None:
        self.hide()
        self._status_label.setText("")
        self.closed.emit()

    #
    # Events
    #

    def _on_option_changed(self, *args) -> None:  # pylint:disable=unused-argument
        self.query_changed.emit()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_Escape:
            self.close_bar()
            event.accept()
            return
        super().keyPressEvent(event)

    def eventFilter(self, obj, event) -> bool:
        if obj is self._query_box and event.type() == QEvent.Type.KeyPress:
            if event.key() == Qt.Key.Key_Escape:
                self.close_bar()
                return True
            if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                    self.find_previous.emit()
                else:
                    self.find_next.emit()
                return True
        return super().eventFilter(obj, event)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self._query_box = QLineEdit(self)
        self._query_box.setPlaceholderText("Find...")
        self._query_box.setClearButtonEnabled(True)
        self._query_box.addAction(
            icon("search", color_role=QPalette.ColorRole.PlaceholderText), QLineEdit.ActionPosition.LeadingPosition
        )
        self._query_box.textChanged.connect(self._on_option_changed)
        self._query_box.installEventFilter(self)
        self._default_text_color = self._query_box.palette().color(QPalette.ColorRole.Text)

        self._prev_button = QToolButton(self)
        self._prev_button.setText("▲")
        self._prev_button.setToolTip("Previous match (Shift+F3)")
        self._prev_button.clicked.connect(self.find_previous.emit)

        self._next_button = QToolButton(self)
        self._next_button.setText("▼")
        self._next_button.setToolTip("Next match (F3)")
        self._next_button.clicked.connect(self.find_next.emit)

        self._case_box = QCheckBox("Aa", self)
        self._case_box.setToolTip("Case sensitive")
        self._case_box.stateChanged.connect(self._on_option_changed)

        self._regex_box = QCheckBox(".*", self)
        self._regex_box.setToolTip("Regular expression")
        self._regex_box.stateChanged.connect(self._on_option_changed)

        self._status_label = QLabel(self)

        close_button = QToolButton(self)
        close_button.setText("✕")
        close_button.setToolTip("Close (Esc)")
        close_button.clicked.connect(self.close_bar)

        if self._modes:
            self._mode_combo = QComboBox(self)
            self._mode_combo.addItems(self._modes)
            self._mode_combo.currentIndexChanged.connect(self._on_option_changed)

        layout = QHBoxLayout()
        layout.addWidget(QLabel("Find:", self))
        if self._mode_combo is not None:
            layout.addWidget(self._mode_combo)
        layout.addWidget(self._query_box, 1)
        layout.addWidget(self._prev_button)
        layout.addWidget(self._next_button)
        layout.addWidget(self._case_box)
        layout.addWidget(self._regex_box)
        layout.addWidget(self._status_label)
        layout.addWidget(close_button)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(3)
        self.setLayout(layout)
