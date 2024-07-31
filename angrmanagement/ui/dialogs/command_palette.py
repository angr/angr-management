from __future__ import annotations

import difflib
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QAbstractItemModel, QMargins, QModelIndex, QRectF, QSize, Qt
from PySide6.QtGui import QBrush, QColor, QTextDocument
from PySide6.QtWidgets import QDialog, QLineEdit, QListView, QStyle, QStyledItemDelegate, QVBoxLayout
from thefuzz import process

from angrmanagement.config import Conf

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function

    from angrmanagement.logic.commands import Command
    from angrmanagement.ui.workspace import Workspace


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

    def rowCount(self, _):
        return len(self._filtered_items)

    def columnCount(self, _) -> int:  # pylint:disable=no-self-use
        return 1

    def index(self, row, col, _):
        return self.createIndex(row, col, None)

    def parent(self, _):  # pylint:disable=no-self-use
        return QModelIndex()

    def data(self, index, role):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        row = index.row()
        return self._filtered_items[row] if row < len(self._filtered_items) else None

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


class CommandPaletteModel(PaletteModel):
    """
    Data provider for command palette.
    """

    def get_items(self) -> list[Command]:
        return sorted(
            [cmd for cmd in self.workspace.command_manager.get_commands() if cmd.is_visible],
            key=lambda cmd: cmd.caption,
        )

    def get_caption_for_item(self, item: Command) -> str:
        return item.caption


class GotoPaletteModel(PaletteModel):
    """
    Data provider for goto palette.
    """

    def get_items(self) -> list[Function]:
        items = []

        instance = self.workspace.main_instance
        if instance and not instance.project.am_none:
            project = instance.project.am_obj
            items.extend([func for _, func in project.kb.functions.items()])

        return items

    def get_icon_color_and_text_for_item(self, item: Function) -> tuple[QColor | None, str]:
        if item.is_syscall:
            color = Conf.function_table_syscall_color
        elif item.is_plt:
            color = Conf.function_table_plt_color
        elif item.is_simprocedure:
            color = Conf.function_table_simprocedure_color
        elif item.alignment:
            color = Conf.function_table_alignment_color
        else:
            color = Qt.GlobalColor.gray
        return (color, "f")

    def get_caption_for_item(self, item: Function) -> str:
        return item.name

    def get_annotation_for_item(self, item: Function) -> str:
        return f"{item.addr:x}"


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
                text_out += text_in[last_idx:idx] + f"<b>{text_in[idx:idx + size]}</b>"
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
            if option.state & QStyle.StateFlag.State_Selected:
                b = QBrush(option.palette.highlight())
                painter.fillRect(option.rect, b)

            model: PaletteModel = index.model()
            item = index.data()

            td = self._get_text_document(index)
            td.setDefaultFont(option.font)

            annotation_text = model.get_annotation_for_item(item)
            if annotation_text:
                painter.drawText(
                    option.rect.marginsRemoved(QMargins(3, 3, 3, 3)),
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                    annotation_text,
                )

            painter.save()
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
            return QSize(width, s.height())
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
        self._view.setCurrentIndex(self._model.index(0, 0, None))

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


class CommandPaletteDialog(PaletteDialog):
    """
    Dialog for selecting commands.
    """

    def __init__(self, workspace: Workspace, parent=None) -> None:
        super().__init__(CommandPaletteModel(workspace), PaletteItemDelegate(display_icons=False), parent)
        self.setWindowTitle("Command Palette")


class GotoPaletteDialog(PaletteDialog):
    """
    Dialog for selecting navigation targets.
    """

    def __init__(self, workspace: Workspace, parent=None) -> None:
        super().__init__(GotoPaletteModel(workspace), parent=parent)
        self.setWindowTitle("Goto Anything")
