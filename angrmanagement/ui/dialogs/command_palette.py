import difflib
from typing import TYPE_CHECKING, Dict, List

from PySide6.QtCore import QAbstractItemModel, QModelIndex, QSize, Qt
from PySide6.QtGui import QBrush, QTextDocument
from PySide6.QtWidgets import QDialog, QLineEdit, QListView, QStyle, QStyledItemDelegate, QVBoxLayout
from thefuzz import process

if TYPE_CHECKING:
    from angrmanagement.logic.commands import Command
    from angrmanagement.ui.workspace import Workspace


class CommandPaletteModel(QAbstractItemModel):
    """
    Data provider for command palette.
    """

    def __init__(self, workspace: "Workspace"):
        super().__init__()
        self.workspace: "Workspace" = workspace
        self._available_commands: List["Command"] = sorted(
            [cmd for cmd in self.workspace.command_manager.get_commands() if cmd.is_visible],
            key=lambda cmd: cmd.caption,
        )
        self._command_to_caption: Dict["Command", str] = {c: c.caption for c in self._available_commands}
        self._filtered_commands: List["Command"] = self._available_commands
        self._filter_text: str = ""

    def rowCount(self, _):
        return len(self._filtered_commands)

    def columnCount(self, _):  # pylint:disable=no-self-use
        return 1

    def index(self, row, col, _):
        return self.createIndex(row, col, None)

    def parent(self, _):  # pylint:disable=no-self-use
        return QModelIndex()

    def data(self, index, role):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        row = index.row()
        return self._filtered_commands[row]

    def set_filter_text(self, query: str):
        """
        Filter the list of available commands by captions matching `query`.
        """
        self.beginResetModel()
        self._filter_text = query
        if query == "":
            self._filtered_commands = self._available_commands
        else:
            self._filtered_commands = [
                command for _, _, command in process.extract(query, self._command_to_caption, limit=50)
            ]
        self.endResetModel()


class CommandPaletteItemDelegate(QStyledItemDelegate):
    """
    Delegate to draw individual command entries in the palette.

    Query sub-sequence matches against command names are shown in bold.
    """

    @staticmethod
    def _get_text_document(index):
        model: CommandPaletteModel = index.model()
        text_in = index.data().caption

        if not model._filter_text:
            text_out = text_in
        else:
            # Render matching sub-sequences in bold
            matcher = difflib.SequenceMatcher(None, text_in.upper(), model._filter_text.upper())
            text_out = ""
            last_idx = 0
            for idx, _, size in matcher.get_matching_blocks():
                text_out += text_in[last_idx:idx] + f"<b>{text_in[idx:idx + size]}</b>"
                last_idx = idx + size
            text_out += text_in[last_idx:]

        td = QTextDocument()
        td.setHtml(text_out)
        return td

    def paint(self, painter, option, index):
        if index.column() == 0:
            if option.state & QStyle.State_Selected:
                b = QBrush(option.palette.highlight())
                painter.fillRect(option.rect, b)

            td = self._get_text_document(index)
            td.setDefaultFont(option.font)
            painter.save()
            painter.translate(option.rect.topLeft())
            td.drawContents(painter)
            painter.restore()
        else:
            super().paint(painter, option, index)

    def sizeHint(self, option, index) -> QSize:
        if index.column() == 0:
            td = self._get_text_document(index)
            td.setDefaultFont(option.font)
            s = td.size()
            return QSize(s.width(), s.height())
        return super().sizeHint(option, index)


class CommandPaletteDialog(QDialog):
    """
    Dialog for selecting commands.
    """

    def __init__(self, workspace, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Command Palette")
        self._model = CommandPaletteModel(workspace)
        self._delegate = CommandPaletteItemDelegate()
        self._init_widgets()
        self.selected_command = None

    def sizeHint(self):  # pylint:disable=no-self-use
        return QSize(500, 400)

    #
    # Private methods
    #

    def _init_widgets(self):
        self._layout: QVBoxLayout = QVBoxLayout()

        self._query: QLineEdit = QLineEdit(self)
        self._query.textChanged.connect(self._set_filter_text)
        self._layout.addWidget(self._query)

        self._view: QListView = QListView(self)
        self._view.setModel(self._model)
        self._view.setItemDelegate(self._delegate)
        self._view.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._view.clicked.connect(self.accept)
        self._layout.addWidget(self._view)

        self.setLayout(self._layout)
        self._set_filter_text("")

    def _set_filter_text(self, text):
        self._model.set_filter_text(text)
        self._view.setCurrentIndex(self._model.index(0, 0, None))

    def _get_selected(self):
        for i in self._view.selectedIndexes():
            return i.data()
        return None

    #
    # Event handlers
    #

    def keyPressEvent(self, event):
        key = event.key()
        if key in {Qt.Key_Up, Qt.Key_Down}:
            self._view.keyPressEvent(event)
        elif key in {Qt.Key_Enter, Qt.Key_Return}:
            self.accept()
        else:
            super().keyPressEvent(event)

    def accept(self):
        self.selected_command = self._get_selected()
        super().accept()
