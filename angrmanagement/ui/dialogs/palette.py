"""
Base palette framework for building palette-style dialogs with fuzzy search.
"""

from __future__ import annotations

import difflib
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QAbstractItemModel, QMargins, QModelIndex, QRectF, QSize, Qt
from PySide6.QtGui import QBrush, QColor, QPalette, QPen, QTextCharFormat, QTextCursor, QTextDocument
from PySide6.QtWidgets import QDialog, QLineEdit, QListView, QStyle, QStyledItemDelegate, QVBoxLayout
from thefuzz import process

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


# pylint:disable=unused-argument,no-self-use
class PaletteModel(QAbstractItemModel):
    """
    Data provider for item palette.
    """

    def __init__(self, workspace: Workspace) -> None:
        super().__init__()
        self.workspace: Workspace = workspace
        self._available_items: list[Any] = self.get_items()
        self._item_to_caption: dict[Any, str] = {
            item: self.get_caption_for_item(item) for item in self._available_items
        }
        self._filtered_items: list[Any] = self._available_items
        self._filter_text: str = ""

    def rowCount(self, parent=None):
        return len(self._filtered_items)

    def columnCount(self, parent=None):
        return 1

    def index(self, row, column, parent=None):
        return self.createIndex(row, column, None)

    def parent(self, index=None):  # type: ignore
        return QModelIndex()

    def data(self, index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        row = index.row()
        return self._filtered_items[row] if 0 <= row < len(self._filtered_items) else None

    def set_filter_text(self, query: str) -> None:
        """
        Filter the list of available items by captions matching `query`.
        """
        self.beginResetModel()
        self._filter_text = query
        if query == "":
            self._filtered_items = self._available_items
        else:
            self._filtered_items = [item for _, _, item in process.extract(query, self._item_to_caption, limit=50)]
        self.endResetModel()

    def get_items(self) -> list[Any]:  # pylint:disable=no-self-use
        return []

    def get_caption_for_item(self, item: Any) -> str:  # pylint:disable=no-self-use,unused-argument
        return ""

    def get_subcaption_for_item(self, item: Any) -> str | None:  # pylint:disable=no-self-use,unused-argument
        return None

    def get_annotation_for_item(self, item: Any) -> str | None:  # pylint:disable=no-self-use,unused-argument
        return None

    # pylint:disable=no-self-use,unused-argument
    def get_icon_color_and_text_for_item(self, item: Any) -> tuple[QColor | None, str]:
        return (None, "")


class PaletteItemDelegate(QStyledItemDelegate):
    """
    Delegate to draw individual palette entries.

    Query sub-sequence matches against item captions are shown in bold.
    """

    icon_width = 25

    def __init__(self, display_icons: bool = True) -> None:
        super().__init__()
        self._display_icons = display_icons

    @staticmethod
    def _get_text_document(index):
        model: PaletteModel = index.model()
        item = index.data()
        text_in = model.get_caption_for_item(item)

        if not model._filter_text:
            text_out = text_in
        else:
            # Render matching sub-sequences in bold
            matcher = difflib.SequenceMatcher(None, text_in.upper(), model._filter_text.upper())
            text_out = ""
            last_idx = 0
            for idx, _, size in matcher.get_matching_blocks():
                if size == 0:
                    # Skip the final zero-length block returned by SequenceMatcher
                    continue
                text_out += text_in[last_idx:idx] + f"<b>{text_in[idx : idx + size]}</b>"
                last_idx = idx + size
            text_out += text_in[last_idx:]

        subcaption = model.get_subcaption_for_item(item)
        if subcaption:
            text_out += "<br/><sub>" + subcaption + "</sub>"

        td = QTextDocument()
        td.setHtml(text_out)
        return td

    def paint(self, painter, option, index) -> None:
        if index.column() == 0:
            painter.save()
            if option.state & QStyle.StateFlag.State_Selected:
                b = QBrush(option.palette.highlight())
                painter.fillRect(option.rect, b)

            model: PaletteModel = index.model()
            item = index.data()

            td = self._get_text_document(index)
            td.setDefaultFont(option.font)

            annotation_text = model.get_annotation_for_item(item)
            if annotation_text:
                if option.state & QStyle.StateFlag.State_Selected:
                    painter.setPen(QPen(option.palette.color(QPalette.ColorRole.HighlightedText)))
                painter.drawText(
                    option.rect.marginsRemoved(QMargins(3, 3, 3, 3)),
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                    annotation_text,
                )

            painter.translate(option.rect.topLeft())

            if self._display_icons:
                icon_rect = QRectF(0, 0, self.icon_width, td.size().height())
                icon_color, icon_text = model.get_icon_color_and_text_for_item(item)
                if icon_color:
                    painter.fillRect(icon_rect, QBrush(QColor(icon_color)))
                if icon_text:
                    painter.setPen(Qt.GlobalColor.white)
                    painter.drawText(icon_rect, Qt.AlignmentFlag.AlignCenter, icon_text)
                painter.translate(self.icon_width, 0)

            if option.state & QStyle.StateFlag.State_Selected:
                cursor = QTextCursor(td)
                cursor.select(QTextCursor.SelectionType.Document)
                char_format = QTextCharFormat()
                char_format.setForeground(option.palette.highlightedText())
                cursor.mergeCharFormat(char_format)

            td.drawContents(painter)
            painter.restore()
        else:
            super().paint(painter, option, index)

    def sizeHint(self, option, index) -> QSize:
        if index.column() == 0:
            td = self._get_text_document(index)
            td.setDefaultFont(option.font)
            s = td.size()
            width = s.width()
            if self._display_icons:
                width += self.icon_width
            return QSize(int(width), int(s.height()))
        return super().sizeHint(option, index)


class PaletteDialog(QDialog):
    """
    Dialog for selecting an item from a palette.
    """

    def __init__(self, model, delegate=None, parent=None) -> None:
        super().__init__(parent)
        self._model = model
        self._delegate = delegate or PaletteItemDelegate()
        self._init_widgets()

        self.selected_item = None

        self.setWindowTitle("Palette")
        self.setMinimumSize(self.sizeHint())
        self.adjustSize()

    def sizeHint(self):  # pylint:disable=no-self-use
        return QSize(500, 400)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
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

    def _set_filter_text(self, text: str) -> None:
        self._model.set_filter_text(text)
        if self._model.rowCount() > 0:
            self._view.setCurrentIndex(self._model.index(0, 0))
        else:
            # Clear current selection/index when there are no rows to avoid out-of-range indexes
            self._view.clearSelection()
            self._view.setCurrentIndex(QModelIndex())

    def _get_selected(self):
        for i in self._view.selectedIndexes():
            return i.data()
        return None

    #
    # Event handlers
    #

    def keyPressEvent(self, event) -> None:
        key = event.key()
        if key in {Qt.Key.Key_Up, Qt.Key.Key_Down}:
            self._view.keyPressEvent(event)
        elif key in {Qt.Key.Key_Enter, Qt.Key.Key_Return}:
            self.accept()
        else:
            super().keyPressEvent(event)

    def accept(self) -> None:
        self.selected_item = self._get_selected()
        super().accept()
