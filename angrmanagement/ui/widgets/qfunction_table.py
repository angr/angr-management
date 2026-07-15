from __future__ import annotations

import contextlib
from functools import partial
from typing import TYPE_CHECKING

from angr.analyses.code_tagging import CodeTags
from angr.rust.utils.demangler import demangle as rust_demangle
from angr.utils.library import get_cpp_function_name
from PySide6.QtCore import SIGNAL, QAbstractTableModel, QEvent, Qt
from PySide6.QtGui import QAction, QBrush, QCursor, QPalette
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.config import Conf
from angrmanagement.data.instance import Instance, ObjectContainer
from angrmanagement.ui.icons import icon
from angrmanagement.ui.menus.function_context_menu import FunctionContextMenu
from angrmanagement.ui.toolbars import FunctionTableToolbar
from angrmanagement.ui.widgets.qfast_table_view import QFastTableView

if TYPE_CHECKING:
    import PySide6
    import PySide6.QtCore
    import PySide6.QtGui
    from angr.knowledge_plugins.functions import Function, FunctionManager

    from angrmanagement.ui.views.functions_view import FunctionsView
    from angrmanagement.ui.workspace import Workspace


class FunctionTableEntry:
    """
    A single entry in the function table as a proxy for the actual Function object.
    """

    __slots__ = ("_funcman", "addr")

    def __init__(self, funcman: FunctionManager, addr: int) -> None:
        self._funcman = funcman
        self.addr = addr

    def _meta_func(self) -> Function | None:
        try:
            return self._funcman.get_by_addr(self.addr, meta_only=True)
        except KeyError:
            return None

    @property
    def is_syscall(self) -> bool:
        func = self._meta_func()
        return bool(func.is_syscall) if func is not None else False

    @property
    def is_plt(self) -> bool:
        return self._funcman.is_plt_cached(self.addr)

    @property
    def is_simprocedure(self) -> bool:
        func = self._meta_func()
        return bool(func.is_simprocedure) if func is not None else False

    @property
    def is_alignment(self) -> bool:
        func = self._meta_func()
        return bool(func.is_alignment) if func is not None else False

    @property
    def from_signature(self) -> str | None:
        return self._funcman.get_from_signature(self.addr)

    @property
    def name(self) -> str:
        return self._funcman.get_func_name(self.addr)

    @property
    def demangled_name(self) -> str:
        func = self._meta_func()
        return func.demangled_name if func is not None else self.name

    @property
    def tags(self) -> list[str]:
        func = self._meta_func()
        return list(func.tags) if func is not None else []

    @property
    def size(self) -> int:
        func = self._meta_func()
        return func.size if func is not None else 0

    @property
    def number_of_blocks(self) -> int:
        return self._funcman.get_func_block_count(self.addr)

    @property
    def cyclomatic_complexity(self) -> int:
        func = self._meta_func()
        return func.cyclomatic_complexity if func is not None else 0

    @property
    def binary_name(self) -> str:
        func = self._meta_func()
        return (func.binary_name or "") if func is not None else ""


class QFunctionTableModel(QAbstractTableModel):
    """
    The table model for QFunctionTable.
    """

    Headers = ["Inline?", "Name", "Tags", "Address", "Binary", "Size", "Blocks", "Complexity"]
    INLINE_COL = 0
    NAME_COL = 1
    TAGS_COL = 2
    ADDRESS_COL = 3
    BINARY_COL = 4
    SIZE_COL = 5
    BLOCKS_COL = 6
    COMPLEXITY_COL = 7

    def __init__(self, workspace: Workspace, instance: Instance, table_view: QFunctionTableView, func_list) -> None:
        super().__init__()

        self._func_list: list[FunctionTableEntry] | None = None
        self._raw_func_list: list[FunctionTableEntry] | None = func_list
        self.workspace = workspace
        self.instance = instance
        self.table_view = table_view
        self._last_filter_keyword = ""
        self._last_show_alignment: bool | None = True
        self._config = Conf
        self._data_cache = {}

    def __len__(self) -> int:
        if self._func_list is not None:
            return len(self._func_list)
        if self._raw_func_list is not None:
            return len(self._raw_func_list)
        return 0

    @property
    def func_list(self) -> list[FunctionTableEntry] | None:
        if self._func_list is not None:
            return self._func_list
        return self._raw_func_list

    @func_list.setter
    def func_list(self, v) -> None:
        self._func_list = None
        self._raw_func_list = v
        self._data_cache.clear()
        self.filter(self.table_view.filter_text, show_alignment=self.table_view.show_alignment_functions)

    def filter(self, keyword, show_alignment: bool = True) -> None:
        if (not keyword and show_alignment) or self._raw_func_list is None:
            # no active filters; remove the filtering
            self._func_list = None
        else:
            extra_columns = self.workspace.plugins.count_func_columns()
            base_func_list = self._raw_func_list
            if (
                self._last_filter_keyword
                and self._last_filter_keyword in keyword
                and show_alignment == self._last_show_alignment
                and self._func_list is not None
            ):
                # incremental filtering
                base_func_list = self._func_list
            self._func_list = [
                func
                for func in base_func_list
                if self._func_match_keyword(func, keyword, extra_columns=extra_columns)
                and (show_alignment or not func.is_alignment)
            ]

        self._last_filter_keyword = keyword
        self._last_show_alignment = show_alignment
        self._data_cache.clear()
        self.emit(SIGNAL("layoutChanged()"))  # type: ignore

    def clear_data_cache(self):
        self._data_cache = {}

    def rowCount(self, *args, **kwargs):  # pylint:disable=unused-argument
        if self.func_list is None:
            return 0
        return len(self.func_list)

    def totalCount(self) -> int:
        if self._raw_func_list is None:
            return 0
        return len(self._raw_func_list)

    def columnCount(self, *args, **kwargs):  # pylint:disable=unused-argument
        return len(self.Headers) + self.workspace.plugins.count_func_columns()

    def headerData(self, section, orientation, role=None):  # pylint:disable=unused-argument
        if role != Qt.ItemDataRole.DisplayRole:
            return None

        if section < len(self.Headers):
            return self.Headers[section]
        else:
            try:
                return self.workspace.plugins.get_func_column(section - len(self.Headers))
            except IndexError:
                # Not enough columns
                return None

    def data(self, index, role=None):
        if not index.isValid():
            return None
        if self.func_list is None:
            return None

        row = index.row()
        if row >= len(self):
            return None

        col = index.column()

        # Add CheckStateRole for the "Inline?" column
        if col == self.INLINE_COL and role == Qt.ItemDataRole.CheckStateRole:
            func = self.func_list[row]  # Get the function for the current row
            if func in self.instance.functions_to_inline:
                return Qt.CheckState.Checked
            return Qt.CheckState.Unchecked

        key = (row, col, role)
        if key in self._data_cache:
            value = self._data_cache[key]
        else:
            value = self._data_uncached(row, col, role)
            self._data_cache[key] = value
        return value

    def _data_uncached(self, row, col, role):
        if self.func_list is None:
            return None

        func: FunctionTableEntry = self.func_list[row]

        if role == Qt.ItemDataRole.DisplayRole:
            if col == self.INLINE_COL:
                return None  # Checkbox handles display
            return self._get_column_text(func, col)

        elif role == Qt.ItemDataRole.ForegroundRole:
            if func.is_syscall:
                color = self._config.function_table_syscall_color
            elif func.is_plt:
                color = self._config.function_table_plt_color
            elif func.is_simprocedure:
                color = self._config.function_table_simprocedure_color
            elif func.is_alignment:
                color = self._config.function_table_alignment_color
            else:
                color = self._config.function_table_color

            # for w in widgets:
            #    w.setFlags(w.flags() & ~Qt.ItemIsEditable)
            #    w.setForeground(color)

            return QBrush(color)

        elif role == Qt.ItemDataRole.BackgroundRole:
            color = self.workspace.plugins.color_func(func)
            if color is None and func.from_signature:
                # default colors
                color = self._config.function_table_signature_bg_color
            return color

        elif role == Qt.ItemDataRole.FontRole:
            return Conf.tabular_view_font

        return None

    def sort(self, column, order=None) -> None:
        if self.func_list is None:
            return None
        self.layoutAboutToBeChanged.emit()
        self.func_list = sorted(
            self.func_list,
            key=lambda f: self._get_column_data(f, column),
            reverse=order == Qt.SortOrder.DescendingOrder,
        )
        self.layoutChanged.emit()

    #
    # Private methods
    #

    def setData(self, index: PySide6.QtCore.QModelIndex, value, role=Qt.ItemDataRole.EditRole) -> bool:
        if self.func_list is None:
            return False

        if not index.isValid():
            return False

        if role == Qt.ItemDataRole.CheckStateRole and index.column() == self.INLINE_COL:
            func = self.func_list[index.row()]
            if not func:
                return False

            if Qt.CheckState(value) == Qt.CheckState.Checked:
                self.instance.functions_to_inline.add(func)
            else:
                self.instance.functions_to_inline.discard(func)

            self.dataChanged.emit(index, index, [role])
            return True

        return super().setData(index, value, role)

    def flags(self, index: PySide6.QtCore.QModelIndex) -> PySide6.QtCore.Qt.ItemFlags:
        flags = super().flags(index)
        if index.column() == self.INLINE_COL:
            flags |= Qt.ItemFlag.ItemIsUserCheckable
        return flags

    def _get_column_data(self, func: FunctionTableEntry, idx: int):
        if idx == self.INLINE_COL:
            return func in self.instance.functions_to_inline
        elif idx == self.NAME_COL:
            if not self.instance.project.am_none and self.instance.project.is_rust_binary:
                return rust_demangle(func.name)
            name = func.demangled_name
            if name != func.name and " " in name:
                name = get_cpp_function_name(name)
            return name
        elif idx == self.TAGS_COL:
            return func.tags
        elif idx == self.ADDRESS_COL:
            return func.addr
        elif idx == self.BINARY_COL:
            return self._get_binary_name(func)
        elif idx == self.SIZE_COL:
            return func.size
        elif idx == self.BLOCKS_COL:
            return func.number_of_blocks
        elif idx == self.COMPLEXITY_COL:
            return func.cyclomatic_complexity
        else:
            return self.workspace.plugins.extract_func_column(func, idx - len(self.Headers))[0]

    def _get_column_text(self, func: FunctionTableEntry, idx: int):
        if idx < len(self.Headers):
            data = self._get_column_data(func, idx)
            if idx == self.ADDRESS_COL:
                return f"{data:x}"
            elif idx == self.TAGS_COL:
                return self._get_tags_display_string(data)
            else:
                return str(data)

        return self.workspace.plugins.extract_func_column(func, idx - len(self.Headers))[1]

    @staticmethod
    def _get_binary_name(func: FunctionTableEntry) -> str:
        return func.binary_name

    TAG_STRS = {
        CodeTags.HAS_XOR: "Xor",
        CodeTags.HAS_BITSHIFTS: "Shift",
        CodeTags.HAS_SQL: "SQL",
    }

    @classmethod
    def _get_tags_display_string(cls, tags):
        return ", ".join(cls.TAG_STRS.get(t, t) for t in tags)

    def _func_match_keyword(self, func: FunctionTableEntry, keyword: str, extra_columns: int = 0) -> bool:
        """
        Check whether the function matches against the given keyword or not.

        :param func:        The function to match on.
        :param str keyword: The keyword to match against.
        :return:            True if the function matches the keyword, False otherwise.
        :rtype:             bool
        """

        keyword = keyword.lower()

        if not keyword:
            return True
        if func.name is not None and keyword in func.name.lower():
            return True
        demangled_name = func.demangled_name
        if demangled_name and keyword in demangled_name.lower():
            return True
        if isinstance(func.addr, int):
            if keyword in f"{func.addr:x}":
                return True
            if keyword in f"{func.addr:#x}":
                return True
        if func.tags and keyword in ",".join(func.tags).lower():
            return True
        if func.binary_name and keyword in self._get_binary_name(func).lower():
            return True
        if extra_columns > 0:
            for idx in range(extra_columns):
                txt = self.workspace.plugins.extract_func_column(func, idx)[1]
                if txt and keyword in txt.lower():
                    return True
        return False


class QFunctionTableHeaderView(QHeaderView):
    """
    The header for QFunctionTableView.
    """

    def contextMenuEvent(  # type: ignore[reportIncompatibleMethodOverride]  # pylint:disable=unused-argument
        self, event: PySide6.QtGui.QContextMenuEvent
    ) -> None:
        menu = QMenu("Column Menu", self)
        for idx in range(self.model().columnCount()):
            column_text = self.model().headerData(idx, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole)
            action = QAction(column_text, self)
            action.setCheckable(True)
            hidden = self.isSectionHidden(idx)
            action.setChecked(not hidden)
            action.setEnabled(hidden or self.visibleSectionCount() > 1)
            action.toggled.connect(partial(self.setSectionVisible, idx))
            menu.addAction(action)
        menu.exec_(QCursor.pos())

    def visibleSectionCount(self):
        return self.model().columnCount() - self.hiddenSectionCount()

    def setSectionVisible(self, idx: int, visible) -> None:
        if visible or self.visibleSectionCount() > 1:
            self.setSectionHidden(idx, not visible)


class QFunctionTableView(QFastTableView):
    """
    The table view for QFunctionTable.

    Backed by :class:`QFastTableView`, which renders only the currently visible rows via a
    ``QGraphicsScene`` so that the table stays responsive for binaries with thousands of
    functions.
    """

    _model: QFunctionTableModel

    def __init__(self, parent, workspace: Workspace, instance: Instance, selection_callback=None) -> None:
        header = QFunctionTableHeaderView(Qt.Orientation.Horizontal)
        super().__init__(parent, header=header)
        self.workspace = workspace
        self.instance = instance
        self._context_menu = FunctionContextMenu(workspace, self)

        self._function_table: QFunctionTable = parent
        self._selected_func = ObjectContainer(None, "Currently selected function")
        self._selected_func.am_subscribe(selection_callback)

        header.setSectionsClickable(True)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        header.setSortIndicatorShown(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        self.set_row_height(24)

        self.show_alignment_functions = False
        self.filter_text = ""
        self._functions = None
        self._model = QFunctionTableModel(self.workspace, self.instance, self, [])

        self.setModel(self._model)

        # Adjusted column widths: Added a width for "Inline?" column (e.g., 30)
        column_widths = [30, 200, 80, 80, 80, 50, 50]  # Shifted original widths
        for idx, width in enumerate(column_widths):
            if idx < self._model.columnCount():  # Ensure we don't go out of bounds
                header.resizeSection(idx, width)

        # slots
        self.row_double_clicked.connect(self._on_function_selected_row)
        self.context_menu_requested.connect(self._on_context_menu_requested)
        self.key_pressed.connect(self._on_key_pressed)

    def refresh(self, added_funcs: set[int] | None = None, removed_funcs: set[int] | None = None) -> None:
        if self._functions is None:
            return
        if added_funcs:
            new_funcs = []
            for addr in added_funcs:
                f_ = FunctionTableEntry(self._functions, addr)
                new_funcs.append(f_)
            if self._model.func_list is None:
                self._model.func_list = new_funcs
            else:
                self._model.func_list += new_funcs
        if removed_funcs and self._model.func_list:
            self._model.func_list = [f_ for f_ in self._model.func_list if f_.addr not in removed_funcs]
        self.viewport_update()

    def changeEvent(self, event):  # type: ignore
        if event.type() == QEvent.Type.PaletteChange:
            self._model.clear_data_cache()
        super().changeEvent(event)

    @property
    def function_manager(self):
        return self._functions

    @function_manager.setter
    def function_manager(self, functions) -> None:
        self._functions = functions
        self.load_functions()

    def subscribe_func_select(self, callback) -> None:
        self._selected_func.am_subscribe(callback)

    def filter(self, keyword, show_alignment: bool = True) -> None:
        self.filter_text = keyword
        self._model.filter(keyword, show_alignment=show_alignment)

    def jump_to_result(self, index: int = 0) -> None:
        if self._model.func_list is not None and len(self._model.func_list) > index:
            func_entry = self._model.func_list[index]
            self._selected_func.am_obj = self._functions.get_by_addr(func_entry.addr, meta_only=True)
            self._selected_func.am_event(func=self._selected_func.am_obj)

    def load_functions(self) -> None:
        """
        Load all functions from FunctionManager and create table entries for them.
        """
        if self._functions is None:
            return
        self._model.func_list = [FunctionTableEntry(self._functions, addr) for addr in self._functions]
        self._model.filter(self.filter_text, show_alignment=self.show_alignment_functions)

    def _on_function_selected_row(self, row: int) -> None:
        if self._model.func_list is None or self._functions is None:
            return
        if not (0 <= row < len(self._model.func_list)):
            return
        func_entry = self._model.func_list[row]
        self._selected_func.am_obj = self._functions.get_by_addr(func_entry.addr, meta_only=True)
        self._selected_func.am_event(func=self._selected_func.am_obj)

    def _on_key_pressed(self, text: str) -> None:
        # show the filtering text box
        self._function_table.show_filter_box(prefix=text)

    def _on_context_menu_requested(self, global_pos: PySide6.QtCore.QPoint) -> None:
        funcs = []
        func_list = self._model.func_list
        if func_list is not None and self.instance.kb is not None and self.instance.kb.functions is not None:
            for row in self.selected_rows():
                if 0 <= row < len(func_list):
                    with contextlib.suppress(KeyError):
                        funcs.append(self.instance.kb.functions[func_list[row].addr])
        self._context_menu.set(funcs).qmenu().popup(global_pos)


class QFunctionTableFilterBox(QLineEdit):
    """
    The filter box for QFunctionTable.
    """

    def __init__(self, parent) -> None:
        super().__init__()

        self._table = parent

        self.installEventFilter(self)

    def eventFilter(self, _, event) -> bool:
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Escape:
            if self.text():
                self.setText("")
            else:
                self._table.clear_filter_box()
            return True

        return False


class QFunctionTable(QWidget):
    """
    Implements a table for listing function details.
    """

    def __init__(self, parent, instance: Instance, selection_callback=None) -> None:
        super().__init__(parent)
        self.instance = instance

        self._view: FunctionsView = parent
        self._table_view: QFunctionTableView
        self._filter_box: QFunctionTableFilterBox
        self._toolbar: FunctionTableToolbar
        self._status_label: QLabel

        self._last_known_func_addrs: set[int] = set()
        self._function_count = None

        self._init_widgets(selection_callback)

    @property
    def show_alignment_functions(self):
        return self._table_view.show_alignment_functions

    @property
    def function_manager(self) -> FunctionManager | None:
        if self._table_view is not None:
            return self._table_view.function_manager
        return None

    @function_manager.setter
    def function_manager(self, v):
        if v is not None:
            self._function_count = len(v)
        if self._table_view is not None:
            self._table_view.function_manager = v
        else:
            raise ValueError("QFunctionTableView is uninitialized.")
        func_list = self._table_view._model.func_list
        self._last_known_func_addrs = {func.addr for func in func_list} if func_list else set()
        self.filter_functions(self._filter_box.text())
        self.update_displayed_function_count()

    #
    # Public methods
    #

    def refresh(self) -> None:
        if self.function_manager is None:
            return

        if self._function_count != len(self.function_manager):
            # the number of functions has increased - we need to update the table
            added_funcs, removed_funcs = self._updated_functions(self.function_manager)
        else:
            added_funcs, removed_funcs = None, None

        self._table_view.refresh(added_funcs=added_funcs, removed_funcs=removed_funcs)
        self._function_count = len(self._last_known_func_addrs)
        self.update_displayed_function_count()

    def show_filter_box(self, prefix: str = "") -> None:
        if prefix:
            self._filter_box.setText(prefix)
        self._filter_box.show()
        self._filter_box.setFocus()

    def clear_filter_box(self) -> None:
        self._filter_box.setText("")
        self._table_view.setFocus()

    def toggle_show_alignment_functions(self) -> None:
        self._table_view.show_alignment_functions = not self._table_view.show_alignment_functions
        self.filter_functions(self._filter_box.text())
        self.update_displayed_function_count()

    def subscribe_func_select(self, callback) -> None:
        self._table_view.subscribe_func_select(callback)

    def update_displayed_function_count(self) -> None:
        cnt = self._table_view._model.rowCount()
        total_cnt = self._table_view._model.totalCount()
        if self.function_manager is None:
            self._status_label.setText("")
            return
        if cnt == total_cnt:
            self._status_label.setText(f"{cnt} functions")
        else:
            self._status_label.setText(f"{cnt}/{total_cnt} functions")

    def filter_functions(self, text: str) -> None:
        self._table_view.filter(text, show_alignment=self._table_view.show_alignment_functions)
        self.update_displayed_function_count()

    #
    # Private methods
    #

    def _init_widgets(self, selection_callback=None) -> None:
        # function table view
        self._table_view = QFunctionTableView(self, self._view.workspace, self.instance, selection_callback)

        # filter text box
        self._filter_box = QFunctionTableFilterBox(self)
        self._filter_box.setClearButtonEnabled(True)
        self._filter_box.addAction(
            icon("search", color_role=QPalette.ColorRole.PlaceholderText), QLineEdit.ActionPosition.LeadingPosition
        )
        self._filter_box.setPlaceholderText("Filter by name...")
        self._filter_box.textChanged.connect(self._on_filter_box_text_changed)
        self._filter_box.returnPressed.connect(self._on_filter_box_return_pressed)

        # toolbar
        self._toolbar = FunctionTableToolbar(self)

        self._status_label = QLabel()

        status_lyt = QHBoxLayout()
        status_lyt.setContentsMargins(3, 3, 3, 3)
        status_lyt.setSpacing(3)
        status_lyt.addWidget(self._toolbar.qtoolbar())
        status_lyt.addWidget(self._filter_box)
        status_lyt.addWidget(self._status_label)

        # layout
        layout = QVBoxLayout()
        layout.addLayout(status_lyt)
        layout.addWidget(self._table_view)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.setLayout(layout)

    def _updated_functions(self, function_manager: FunctionManager) -> tuple[set[int], set[int]]:
        if len(self._last_known_func_addrs) == len(function_manager.function_addrs_set):
            return set(), set()
        new_func_addrs_set = function_manager.function_addrs_set.copy()
        added = new_func_addrs_set.difference(self._last_known_func_addrs)
        removed = self._last_known_func_addrs.difference(new_func_addrs_set)
        self._last_known_func_addrs = new_func_addrs_set
        return added, removed

    #
    # Events
    #

    def _on_filter_box_text_changed(self, text: str) -> None:
        self.filter_functions(text)

    def _on_filter_box_return_pressed(self) -> None:
        self._table_view.jump_to_result()
        self.clear_filter_box()
