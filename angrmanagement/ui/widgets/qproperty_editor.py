# pylint:disable=no-self-use,unused-argument
from __future__ import annotations

import sys
from enum import Enum, auto
from typing import Any, ClassVar, Generic, TypeVar

from PySide6.QtCore import (
    QAbstractItemModel,
    QEvent,
    QModelIndex,
    QPersistentModelIndex,
    QRect,
    QSortFilterProxyModel,
    Qt,
    Signal,
)
from PySide6.QtGui import QBrush, QColor, QFont, QMouseEvent, QPalette, QPen, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QColorDialog,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFontDialog,
    QHBoxLayout,
    QLineEdit,
    QSpinBox,
    QSplitter,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTextEdit,
    QToolButton,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.ui.icons import icon


class PropertyType(Enum):
    """
    PropertyItem types.
    """

    INVALID = auto()
    GROUP = auto()
    INT = auto()
    TEXT = auto()
    COMBO = auto()
    FLOAT = auto()
    COLOR = auto()
    BOOL = auto()
    FONT = auto()
    FILE = auto()


T = TypeVar("T")


class PropertyItem:
    """
    Base PropertyItem. Don't use this directly.
    """

    type: ClassVar[PropertyType] = PropertyType.INVALID

    def __init__(self, name: str, description: str = "", **kwargs):
        assert self.type != PropertyType.INVALID
        self.name = name
        self.description = description
        self.parent: PropertyItem | None = None
        self.children: list[PropertyItem] = []
        for prop in kwargs.pop("children", []):
            self.addChild(prop)
        self.extra: dict[str, Any] = kwargs

    def childCount(self):
        return len(self.children)

    def child(self, row):
        if 0 <= row < len(self.children):
            return self.children[row]
        return None

    def row(self):
        if self.parent:
            return self.parent.children.index(self)
        return 0

    def addChild(self, child):
        child.parent = self
        self.children.append(child)


class GroupPropertyItem(PropertyItem):
    """
    Property group item.
    """

    type: ClassVar[PropertyType] = PropertyType.GROUP


class ValuePropertyItem(PropertyItem, Generic[T]):
    """
    Generic value property.
    """

    initial_value: T
    value: T

    def __init__(self, name: str, value: T, description: str = "", **kwargs):
        super().__init__(name, description=description, **kwargs)
        self.initial_value = value
        self.value = value

    @property
    def is_value_modified(self) -> bool:
        return self.value != self.initial_value


class BoolPropertyItem(ValuePropertyItem[bool]):
    """
    Boolean value property.
    """

    type: ClassVar[PropertyType] = PropertyType.BOOL

    def __init__(self, name: str, value: bool, description: str = "", **kwargs):
        super().__init__(name, value, description=description, **kwargs)


class ComboPropertyItem(ValuePropertyItem[Any]):
    """
    Combo property.
    """

    type: ClassVar[PropertyType] = PropertyType.COMBO
    choices: dict[Any, str]

    def __init__(self, name: str, value: Any, choices: list[Any] | dict[Any, str], description: str = "", **kwargs):
        super().__init__(name, value, description=description, **kwargs)
        assert isinstance(choices, list | dict)
        self.choices = {c: c for c in choices} if isinstance(choices, list) else choices


class IntPropertyItem(ValuePropertyItem[int]):
    """
    Integer property.
    """

    type: ClassVar[PropertyType] = PropertyType.INT

    def __init__(
        self, name: str, value: int, minimum: int = -(2**31), maximum: int = 2**31 - 1, description: str = "", **kwargs
    ):
        super().__init__(name, value, description=description, **kwargs)
        self.minimum = minimum
        self.maximum = maximum


class FloatPropertyItem(ValuePropertyItem[float]):
    """
    Real number property.
    """

    type: ClassVar[PropertyType] = PropertyType.FLOAT

    # FIXME: Float max, min
    def __init__(
        self,
        name: str,
        value: float,
        minimum: float = sys.float_info.min,
        maximum: float = sys.float_info.max,
        description: str = "",
        **kwargs,
    ):
        super().__init__(name, value, description=description, **kwargs)
        self.minimum = minimum
        self.maximum = maximum


class TextPropertyItem(ValuePropertyItem[str]):
    """
    Text property.
    """

    type: ClassVar[PropertyType] = PropertyType.TEXT


class FilePropertyItem(ValuePropertyItem[str]):
    """
    File path property.
    """

    type: ClassVar[PropertyType] = PropertyType.FILE


class ColorPropertyItem(ValuePropertyItem[QColor]):
    """
    Color property.
    """

    type: ClassVar[PropertyType] = PropertyType.COLOR


class FontPropertyItem(ValuePropertyItem[QFont]):
    """
    Font property.
    """

    type: ClassVar[PropertyType] = PropertyType.FONT


class PropertyModel(QAbstractItemModel):
    """
    Property tree model.
    """

    valueChanged = Signal(object, object)  # Emits (propertyItem, newValue)

    def __init__(self, root, parent=None):
        super().__init__(parent)
        self.rootItem = root

    def columnCount(self, parent=None):
        return 2

    def rowCount(self, parent=None):
        parentItem = parent.internalPointer() if parent and parent.isValid() else self.rootItem
        return parentItem.childCount()

    def index(self, row, column, parent=None):
        parent = parent or QModelIndex()
        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        parentItem = parent.internalPointer() if parent.isValid() else self.rootItem
        childItem = parentItem.child(row)
        if childItem:
            return self.createIndex(row, column, childItem)
        return QModelIndex()

    def parent(self, index=None):  # type:ignore
        index = index or QModelIndex()
        if not index.isValid():
            return QModelIndex()
        childItem = index.internalPointer()
        parentItem = childItem.parent
        if parentItem == self.rootItem or parentItem is None:
            return QModelIndex()
        return self.createIndex(parentItem.row(), 0, parentItem)

    def data(self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        item = index.internalPointer()
        column = index.column()

        if item.type == PropertyType.GROUP:
            if role == Qt.ItemDataRole.BackgroundRole:
                return QBrush(QApplication.palette().color(QPalette.ColorRole.Mid))
            if role == Qt.ItemDataRole.FontRole:
                font = QFont()
                font.setBold(True)
                return font

        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole):
            if column == 0:
                return item.name
            elif column == 1:
                match item.type:
                    case PropertyType.GROUP:
                        return ""
                    case PropertyType.TEXT:
                        return item.value
                    case PropertyType.INT | PropertyType.FLOAT:
                        return str(item.value)
                    case PropertyType.BOOL:
                        return ""  # Checkbox is rendered.
                    case PropertyType.COLOR:
                        return item.value.name()
                    case PropertyType.FONT:
                        return f"{item.value.family()}, {item.value.pointSize()}pt"
                    case PropertyType.FILE:
                        return item.value if item.value is not None else ""
                    case PropertyType.COMBO:
                        return item.choices[item.value]
                    case _:
                        raise NotImplementedError(item.type)

        if (
            role == Qt.ItemDataRole.DecorationRole
            and column == 1
            and item.type == PropertyType.COLOR
            and isinstance(item.value, QColor)
        ):
            pixmap = QPixmap(16, 16)
            pixmap.fill(item.value)
            return pixmap

        if role == Qt.ItemDataRole.CheckStateRole and column == 1 and item.type == PropertyType.BOOL:
            return Qt.CheckState.Checked if item.value else Qt.CheckState.Unchecked

        # Show modified properties in bold.
        if role == Qt.ItemDataRole.FontRole and item.type != PropertyType.GROUP and item.value != item.initial_value:
            font = QFont()
            font.setBold(True)
            return font

        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return "Property" if section == 0 else "Value"
        return None

    def flags(self, index):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        item = index.internalPointer()
        flags = Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled
        if index.column() == 1 and item.type != PropertyType.GROUP:
            flags |= Qt.ItemFlag.ItemIsEditable
        if item.type == PropertyType.BOOL:
            flags |= Qt.ItemFlag.ItemIsUserCheckable
        return flags

    def setData(
        self, index: QModelIndex | QPersistentModelIndex, value: Any, role: int = Qt.ItemDataRole.EditRole
    ) -> bool:
        if not index.isValid():
            return False
        item = index.internalPointer()
        if index.column() == 1:
            match item.type:
                case PropertyType.INT:
                    try:
                        item.value = int(value)
                    except ValueError:
                        return False
                case PropertyType.FLOAT:
                    try:
                        item.value = float(value)
                    except ValueError:
                        return False
                case PropertyType.BOOL:
                    if value in (Qt.CheckState.Checked, Qt.CheckState.Unchecked):
                        item.value = value == Qt.CheckState.Checked
                    else:
                        item.value = bool(value)
                case PropertyType.COLOR:
                    if isinstance(value, QColor):
                        item.value = value
                    else:
                        return False
                case PropertyType.FONT:
                    if isinstance(value, QFont):
                        item.value = value
                    else:
                        return False
                case PropertyType.FILE:
                    if isinstance(value, str):
                        item.value = value
                    else:
                        return False
                case _:
                    item.value = value
            self.dataChanged.emit(index, index, [role])
            name_idx = self.index(index.row(), 0, index.parent())
            self.dataChanged.emit(name_idx, name_idx, [Qt.ItemDataRole.DisplayRole])
            self.valueChanged.emit(item, item.value)
            return True
        return False


def for_all_model_rows(model, callback) -> None:
    """Iterate over all rows in the model."""
    stack = [QModelIndex()]
    while stack:
        parent = stack.pop()
        callback(parent)

        for row in range(model.rowCount(parent)):
            index = model.index(row, 0, parent)
            if not index.isValid():
                continue
            stack.append(index)


def get_level(index) -> int:
    """Returns the hierarchical depth level of the given index."""
    level = 0
    while index.parent().isValid():
        index = index.parent()
        level += 1
    return level


class PropertyDelegate(QStyledItemDelegate):
    """
    Property tree delegate.
    """

    @staticmethod
    def _get_source_item(index):
        # If the index is from a proxy model, map to source.
        model = index.model()
        if hasattr(model, "mapToSource"):
            source_index = model.mapToSource(index)
            return source_index.internalPointer()
        return index.internalPointer()

    def createEditor(
        self, parent: QWidget, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex
    ) -> QWidget:
        item = self._get_source_item(index)
        match item.type:
            case PropertyType.INT:
                editor = QSpinBox(parent)
                editor.setRange(item.minimum, item.maximum)
                return editor
            case PropertyType.FLOAT:
                editor = QDoubleSpinBox(parent)
                editor.setDecimals(item.extra.get("decimals", 2))
                editor.setRange(item.minimum, item.maximum)
                return editor
            case PropertyType.TEXT:
                return QLineEdit(parent)
            case PropertyType.COMBO:
                editor = QComboBox(parent)
                for data, text in item.choices.items():
                    editor.addItem(text, data)
                return editor
            case PropertyType.BOOL | PropertyType.COLOR | PropertyType.FONT | PropertyType.FILE:
                return None  # type:ignore
            case _:
                pass
        return super().createEditor(parent, option, index)

    def setEditorData(self, editor, index):
        item = self._get_source_item(index)
        value = item.value
        match item.type:
            case PropertyType.INT:
                editor.setValue(int(value))
            case PropertyType.FLOAT:
                editor.setValue(float(value))
            case PropertyType.TEXT:
                editor.setText(str(value))
            case PropertyType.COMBO:
                idx = editor.findData(value)
                if idx >= 0:
                    editor.setCurrentIndex(idx)
            case _:
                super().setEditorData(editor, index)

    def setModelData(self, editor, model, index):
        item = self._get_source_item(index)
        match item.type:
            case PropertyType.INT | PropertyType.FLOAT:
                model.setData(index, editor.value(), Qt.ItemDataRole.EditRole)
            case PropertyType.TEXT:
                model.setData(index, editor.text(), Qt.ItemDataRole.EditRole)
            case PropertyType.COMBO:
                model.setData(index, editor.currentData(), Qt.ItemDataRole.EditRole)
            case _:
                super().setModelData(editor, model, index)

    def updateEditorGeometry(self, editor, option, index):
        if editor:
            editor.setGeometry(option.rect)

    def editorEvent(self, event, model, option, index):
        item = self._get_source_item(index)
        if isinstance(event, QMouseEvent):

            single_clicked_on_value = (
                event.type() == QEvent.Type.MouseButtonRelease
                and event.button() == Qt.MouseButton.LeftButton
                and index.column() == 1
            )
            double_clicked_on_value = (
                event.type() == QEvent.Type.MouseButtonDblClick
                and event.button() == Qt.MouseButton.LeftButton
                and index.column() == 1
            )

            match item.type:
                case PropertyType.COLOR:
                    if double_clicked_on_value:
                        current_color = item.value if isinstance(item.value, QColor) else QColor("white")
                        new_color = QColorDialog.getColor(
                            current_color,
                            option.widget,
                            "Select Color",
                            QColorDialog.ColorDialogOption.ShowAlphaChannel,
                        )
                        if new_color.isValid():
                            model.setData(index, new_color, Qt.ItemDataRole.EditRole)
                        return True
                    return False
                case PropertyType.FONT:
                    if double_clicked_on_value:
                        current_font = item.value if hasattr(item.value, "family") else QFont()
                        ok, font = QFontDialog.getFont(current_font, option.widget, "Select Font")
                        if ok:
                            model.setData(index, font, Qt.ItemDataRole.EditRole)
                        return True
                    return False
                case PropertyType.FILE:
                    if double_clicked_on_value:
                        file_path, _ = QFileDialog.getOpenFileName(option.widget, "Select File", "", "All Files (*)")
                        if file_path:
                            model.setData(index, file_path, Qt.ItemDataRole.EditRole)
                        return True
                    return False
                case PropertyType.BOOL:
                    if single_clicked_on_value:
                        new_value = not item.value
                        model.setData(
                            index,
                            Qt.CheckState.Checked if new_value else Qt.CheckState.Unchecked,
                            Qt.ItemDataRole.EditRole,
                        )
                        return True
                    return False
                case _:
                    pass
        return super().editorEvent(event, model, option, index)

    def paint(self, painter, option, index):
        item = self._get_source_item(index)
        widget = option.widget
        style = widget.style() if widget else QApplication.style()
        palette = widget.palette()
        grid_color = palette.color(palette.ColorRole.Mid)

        # Get full row width
        row_rect = QRect(option.rect)
        row_rect.setLeft(widget.viewport().rect().left())
        row_rect.setRight(widget.viewport().rect().right())

        opt = QStyleOptionViewItem(option)
        opt_rect: QRect = opt.rect  # type: ignore

        if index.column() == 0:
            # Draw group background color
            if item.type == PropertyType.GROUP:
                painter.fillRect(row_rect, index.data(Qt.ItemDataRole.BackgroundRole))

            # Draw row highlight manually to ensure full row coverage
            if opt.state & QStyle.State_Selected:  # type: ignore
                style.drawPrimitive(QStyle.PrimitiveElement.PE_PanelItemViewItem, option, painter, widget)

            # Adjust for gutter
            opt_rect.adjust(opt_rect.height(), 0, 0, 0)

            # Indent levels
            indentation_per_level = 15
            level = get_level(index)
            if level > 1:
                opt_rect.adjust((level - 1) * indentation_per_level, 0, 0, 0)

        super().paint(painter, opt, index)

        if index.column() == 0:
            # Draw expand control
            branch = QStyleOptionViewItem()
            branch.rect = QRect(row_rect.x(), opt_rect.y(), opt_rect.height(), opt_rect.height())  # type: ignore
            branch.state = option.state  # type: ignore
            style.drawPrimitive(QStyle.PrimitiveElement.PE_IndicatorBranch, branch, painter)

        # Draw horizontal grid line
        painter.save()
        pen = QPen(grid_color, 1, Qt.PenStyle.SolidLine)  # Set grid color and thickness
        painter.setPen(pen)
        painter.drawLine(row_rect.bottomLeft(), row_rect.bottomRight())
        painter.restore()


class PropertyFilterProxy(QSortFilterProxyModel):
    """
    A proxy model for filtering displayed property tree items.
    """

    def filterAcceptsRow(self, source_row, source_parent):
        index0 = self.sourceModel().index(source_row, 0, source_parent)
        if not index0.isValid():
            return False
        # Filter based on property name.
        filter_text = self.filterRegularExpression().pattern().lower()
        if not filter_text:
            return True
        prop_name = self.sourceModel().data(index0, Qt.ItemDataRole.DisplayRole)
        return prop_name and filter_text in prop_name.lower()


class PropertyTreeView(QTreeView):
    """
    QTreeView subclass to correctly handle expand/collapse clicks with custom delegate painter that adjusts
    indentation and expand control placement.
    """

    def __init__(self):
        super().__init__()

        # Disable expand/collapse controls. We'll handle it manually.
        self.setItemsExpandable(False)
        self.setStyleSheet(
            """
            QTreeView::item {
                padding: 2px;
            }
            QTreeView::branch {
                border-image: none;
                image: none;
            }
        """
        )

    def mouseDoubleClickEvent(self, event):
        index = self.indexAt(event.pos())
        if index.isValid() and index.column() == 0:
            self.setExpanded(index, not self.isExpanded(index))
            return
        super().mouseDoubleClickEvent(event)

    def mousePressEvent(self, event):
        """Intercept mouse events to properly handle clicks on the expand/collapse indicator."""

        index = self.indexAt(event.pos())  # Get the clicked index
        if not index.isValid():
            super().mousePressEvent(event)
            return

        indicator_rect = QRect(self.visualRect(index))
        indicator_rect.setLeft(self.viewport().rect().x())
        indicator_rect.setWidth(indicator_rect.height())

        # If click is within the indicator area, manually trigger expand/collapse
        if indicator_rect.contains(event.pos()):
            self.setExpanded(index, not self.isExpanded(index))
            return  # Prevent further event propagation

        # Otherwise, proceed with the normal event handling
        super().mousePressEvent(event)


class QPropertyEditor(QWidget):
    """
    Main widget with a text filter box, the main tree view, and a description box.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        search_icon = icon("search", color_role=QPalette.ColorRole.PlaceholderText)
        assert search_icon is not None

        tools_layout = QHBoxLayout()
        tools_layout.setContentsMargins(0, 0, 0, 0)
        tools_layout.setSpacing(3)

        self._filter_box = QLineEdit()
        self._filter_box.setClearButtonEnabled(True)
        self._filter_box.addAction(search_icon, QLineEdit.ActionPosition.LeadingPosition)
        self._filter_box.setPlaceholderText("Filter by name...")
        self._filter_box.textChanged.connect(self._on_filter_text_changed)
        tools_layout.addWidget(self._filter_box)

        docs_icon = icon("docs")
        assert docs_icon is not None

        self._desc_btn = QToolButton()
        self._desc_btn.setIcon(docs_icon)
        self._desc_btn.setCheckable(True)
        self._desc_btn.setChecked(True)
        tools_layout.addWidget(self._desc_btn)

        self._tree_view = PropertyTreeView()
        self._tree_view.setAutoScroll(False)
        self._tree_view.setAlternatingRowColors(True)
        self._tree_view.setItemDelegate(PropertyDelegate())
        self._tree_view.expandAll()
        self._tree_view.expanded.connect(self._on_item_expanded_or_collapsed)
        self._tree_view.collapsed.connect(self._on_item_expanded_or_collapsed)

        self._desc_box = QTextEdit()
        self._desc_box.setReadOnly(True)
        self._desc_btn.clicked.connect(lambda: self._desc_box.setVisible(self._desc_btn.isChecked()))

        splitter = QSplitter()
        splitter.setOrientation(Qt.Orientation.Vertical)
        splitter.addWidget(self._tree_view)
        splitter.addWidget(self._desc_box)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 0)
        splitter.setSizes([100, 75])

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(3)
        main_layout.addLayout(tools_layout)
        main_layout.addWidget(splitter)

        self._updating_expansion: bool = False
        self._expansion_preference: set[PropertyItem] = set()

        self._proxy_model = PropertyFilterProxy()
        self._proxy_model.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._proxy_model.setRecursiveFilteringEnabled(True)

    def set_description_visible(self, visible: bool = True):
        self._desc_btn.setVisible(visible)
        self._desc_btn.setChecked(visible)
        self._desc_box.setVisible(visible)

    def _on_filter_text_changed(self, text: str):
        self._updating_expansion = True
        self._proxy_model.setFilterFixedString(text)
        self._updating_expansion = False
        self._restore_expansion_state()

    def _save_expansion_state(self):
        def on_node(index):
            if index.isValid() and self._tree_view.isExpanded(index):
                source_index = self._proxy_model.mapToSource(index)
                self._expansion_preference.add(source_index.internalPointer())

        self._expansion_preference.clear()
        for_all_model_rows(self._proxy_model, on_node)

    def _restore_expansion_state(self):
        def on_node(index):
            source_index = self._proxy_model.mapToSource(index)
            prop = source_index.internalPointer()
            if prop in self._expansion_preference:
                self._tree_view.setExpanded(index, True)

        self._updating_expansion = True
        for_all_model_rows(self._proxy_model, on_node)
        self._updating_expansion = False

    def _on_item_expanded_or_collapsed(self, _):
        if not self._updating_expansion:
            self._save_expansion_state()

    def _on_item_selected(self, current, _):
        if current.isValid():
            source_index = self._proxy_model.mapToSource(current)
            item = source_index.internalPointer()
            self._desc_box.setHtml(f"<b>{item.name}</b><br>{item.description}")
        else:
            self._desc_box.clear()

    def setModel(self, model):
        self._desc_box.clear()
        self._proxy_model.setSourceModel(model)
        self._tree_view.setModel(self._proxy_model)
        self._tree_view.selectionModel().currentChanged.connect(self._on_item_selected)
        self._tree_view.setIndentation(0)
        self._tree_view.expandAll()
        self._tree_view.setColumnWidth(0, 300)
