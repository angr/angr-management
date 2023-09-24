import os
import string
from functools import partial
from typing import TYPE_CHECKING, List, Optional, Set, Tuple

import qtawesome as qta
from angr.analyses.code_tagging import CodeTags
from cle.backends.uefi_firmware import UefiPE
from PySide6.QtCore import SIGNAL, QAbstractTableModel, QEvent, Qt
from PySide6.QtGui import QAction, QBrush, QColor, QCursor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.config import Conf
from angrmanagement.data.instance import ObjectContainer
from angrmanagement.ui.menus.function_context_menu import FunctionContextMenu
from angrmanagement.ui.toolbars import FunctionTableToolbar

if TYPE_CHECKING:
    import PySide6
    from angr.knowledge_plugins.functions import Function, FunctionManager

    from angrmanagement.ui.views.functions_view import FunctionsView


class QFunctionTableModel(QAbstractTableModel):
    """
    The table model for QFunctionTable.
    """

    Headers = ["Name", "Tags", "Address", "Binary", "Size", "Blocks"]
    NAME_COL = 0
    TAGS_COL = 1
    ADDRESS_COL = 2
    BINARY_COL = 3
    SIZE_COL = 4
    BLOCKS_COL = 5

    def __init__(self, workspace, instance, func_list):
        super().__init__()

        self._func_list = None
        self._raw_func_list = func_list
        self.workspace = workspace
        self.instance = instance
        self._config = Conf
        self._data_cache = {}

    def __len__(self):
        if self._func_list is not None:
            return len(self._func_list)
        if self._raw_func_list is not None:
            return len(self._raw_func_list)
        return 0

    @property
    def func_list(self) -> List["Function"]:
        if self._func_list is not None:
            return self._func_list
        return self._raw_func_list

    @func_list.setter
    def func_list(self, v):
        self._func_list = None
        self._raw_func_list = v
        self._data_cache.clear()
        self.emit(SIGNAL("layoutChanged()"))

    def filter(self, keyword):
        if not keyword or self._raw_func_list is None:
            # remove the filtering
            self._func_list = None
        else:
            extra_columns = self.workspace.plugins.count_func_columns()
            self._func_list = [
                func
                for func in self._raw_func_list
                if self._func_match_keyword(func, keyword, extra_columns=extra_columns)
            ]

        self._data_cache.clear()
        self.emit(SIGNAL("layoutChanged()"))

    def rowCount(self, *args, **kwargs):  # pylint:disable=unused-argument
        if self.func_list is None:
            return 0
        return len(self.func_list)

    def columnCount(self, *args, **kwargs):  # pylint:disable=unused-argument
        return len(self.Headers) + self.workspace.plugins.count_func_columns()

    def headerData(self, section, orientation, role):  # pylint:disable=unused-argument
        if role != Qt.DisplayRole:
            return None

        if section < len(self.Headers):
            return self.Headers[section]
        else:
            try:
                return self.workspace.plugins.get_func_column(section - len(self.Headers))
            except IndexError:
                # Not enough columns
                return None

    def data(self, index, role):
        if not index.isValid():
            return None

        row = index.row()
        if row >= len(self):
            return None

        col = index.column()

        key = (row, col, role)
        if key in self._data_cache:
            value = self._data_cache[key]
        else:
            value = self._data_uncached(row, col, role)
            self._data_cache[key] = value
        return value

    def _data_uncached(self, row, col, role):
        func = self.func_list[row]

        if role == Qt.DisplayRole:
            return self._get_column_text(func, col)

        elif role == Qt.ForegroundRole:
            if func.is_syscall:
                color = self._config.function_table_syscall_color
            elif func.is_plt:
                color = self._config.function_table_plt_color
            elif func.is_simprocedure:
                color = self._config.function_table_simprocedure_color
            elif func.alignment:
                color = self._config.function_table_alignment_color
            else:
                color = self._config.function_table_color

            # for w in widgets:
            #    w.setFlags(w.flags() & ~Qt.ItemIsEditable)
            #    w.setForeground(color)

            return QBrush(color)

        elif role == Qt.BackgroundColorRole:
            color = self.workspace.plugins.color_func(func)
            if color is None:
                # default colors
                if func.from_signature:
                    color = self._config.function_table_signature_bg_color
            return color

        elif role == Qt.FontRole:
            return Conf.tabular_view_font

        return None

    def sort(self, column, order):
        self.layoutAboutToBeChanged.emit()
        self.func_list = sorted(
            self.func_list, key=lambda f: self._get_column_data(f, column), reverse=order == Qt.DescendingOrder
        )
        self.layoutChanged.emit()

    #
    # Private methods
    #

    def _get_column_data(self, func, idx):
        if idx == self.NAME_COL:
            return func.demangled_name
        elif idx == self.TAGS_COL:
            return func.tags
        elif idx == self.ADDRESS_COL:
            return func.addr
        elif idx == self.BINARY_COL:
            return self._get_binary_name(func)
        elif idx == self.SIZE_COL:
            return func.size
        elif idx == self.BLOCKS_COL:
            return len(func.block_addrs_set)
        else:
            return self.workspace.plugins.extract_func_column(func, idx - len(self.Headers))[0]

    def _get_column_text(self, func, idx):
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
    def _get_binary_name(func) -> str:
        if func.binary is not None:
            if func.binary.binary is not None:
                return os.path.basename(func.binary.binary)
            if isinstance(func.binary, UefiPE):
                if func.binary.user_interface_name:
                    return func.binary.user_interface_name
                if func.binary.guid:
                    return str(func.binary.guid)
                return str(func.binary)
        return ""

    def _get_function_backcolor(self, func) -> QColor:
        return self._backcolor_callback(func)

    TAG_STRS = {
        CodeTags.HAS_XOR: "Xor",
        CodeTags.HAS_BITSHIFTS: "Shift",
        CodeTags.HAS_SQL: "SQL",
    }

    @classmethod
    def _get_tags_display_string(cls, tags):
        return ", ".join(cls.TAG_STRS.get(t, t) for t in tags)

    def _func_match_keyword(self, func, keyword, extra_columns: int = 0):
        """
        Check whether the function matches against the given keyword or not.

        :param func:        The function to match on.
        :param str keyword: The keyword to match against.
        :return:            True if the function matches the keyword, False otherwise.
        :rtype:             bool
        """

        keyword = keyword.lower()

        if keyword in func.name.lower():
            return True
        demangled_name = func.demangled_name
        if demangled_name and keyword in demangled_name.lower():
            return True
        if isinstance(func.addr, int):
            if keyword in "%x" % func.addr:
                return True
            if keyword in "%#x" % func.addr:
                return True
        if keyword in ",".join(func.tags).lower():
            return True
        if func.binary and keyword in self._get_binary_name(func).lower():
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

    def contextMenuEvent(self, event: "PySide6.QtGui.QContextMenuEvent") -> None:  # pylint:disable=unused-argument
        menu = QMenu("Column Menu", self)
        for idx in range(self.model().columnCount()):
            column_text = self.model().headerData(idx, Qt.Orientation.Horizontal, Qt.DisplayRole)
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

    def setSectionVisible(self, idx, visible):
        if visible or self.visibleSectionCount() > 1:
            self.setSectionHidden(idx, not visible)


class QFunctionTableView(QTableView):
    """
    The table view for QFunctionTable.
    """

    def __init__(self, parent, workspace, instance, selection_callback=None):
        super().__init__(parent)
        self.workspace = workspace
        self.instance = instance
        self._context_menu = FunctionContextMenu(workspace, self)

        self._function_table: QFunctionTable = parent
        self._selected_func = ObjectContainer(None, "Currently selected function")
        self._selected_func.am_subscribe(selection_callback)

        header = QFunctionTableHeaderView(Qt.Orientation.Horizontal, self)
        header.setSectionsClickable(True)
        self.setHorizontalHeader(header)
        self.horizontalHeader().setVisible(True)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self.show_alignment_functions = False
        self.filter_text = ""
        self._functions = None
        self._model = QFunctionTableModel(self.workspace, self.instance, [])

        self.setModel(self._model)

        self.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.horizontalHeader().setSortIndicatorShown(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().setDefaultSectionSize(24)

        column_widths = [200, 80, 80, 80, 50, 50]
        for idx, width in enumerate(column_widths):
            self.setColumnWidth(idx, width)

        # slots
        self.horizontalHeader().sortIndicatorChanged.connect(self.sortByColumn)
        self.doubleClicked.connect(self._on_function_selected)

    def refresh(self, added_funcs: Optional[Set[int]] = None, removed_funcs: Optional[Set[int]] = None):
        if added_funcs:
            new_funcs = []
            for addr in added_funcs:
                try:
                    f_ = self._functions[addr]
                except KeyError:
                    continue
                if self.show_alignment_functions or (not self.show_alignment_functions and not f_.alignment):
                    new_funcs.append(f_)
            self._model.func_list += new_funcs
        if removed_funcs:
            self._model.func_list = [f_ for f_ in self._model.func_list if f_.addr not in removed_funcs]
        self.viewport().update()

    @property
    def function_manager(self):
        return self._functions

    @function_manager.setter
    def function_manager(self, functions):
        self._functions = functions
        self.load_functions()

    def subscribe_func_select(self, callback):
        self._selected_func.am_subscribe(callback)

    def filter(self, keyword):
        self.filter_text = keyword
        self._model.filter(keyword)

    def jump_to_result(self, index=0):
        if len(self._model.func_list) > index:
            self._selected_func.am_obj = self._model.func_list[index]
            self._selected_func.am_event(func=self._selected_func.am_obj)

    def load_functions(self):
        if not self.show_alignment_functions:
            self._model.func_list = [v for v in self._functions.values() if not v.alignment]
        else:
            self._model.func_list = list(self._functions.values())
        self._model.filter(self.filter_text)

    def _on_function_selected(self, model_index):
        row = model_index.row()
        self._selected_func.am_obj = self._model.func_list[row]
        self._selected_func.am_event(func=self._selected_func.am_obj)

    def keyPressEvent(self, key_event):
        text = key_event.text()
        if not text or text not in string.printable or text in string.whitespace:
            # modifier keys
            return super().keyPressEvent(key_event)

        # show the filtering text box
        self._function_table.show_filter_box(prefix=text)
        return True

    def contextMenuEvent(self, event: "PySide6.QtGui.QContextMenuEvent") -> None:  # pylint:disable=unused-argument
        rows = self.selectionModel().selectedRows()
        funcs = [self.instance.kb.functions[r.data()] for r in rows]
        self._context_menu.set(funcs).qmenu().popup(QCursor.pos())


class QFunctionTableFilterBox(QLineEdit):
    """
    The filter box for QFunctionTable.
    """

    def __init__(self, parent):
        super().__init__()

        self._table = parent

        self.installEventFilter(self)

    def eventFilter(self, obj, event):  # pylint:disable=unused-argument
        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Escape:
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

    def __init__(self, parent, instance, selection_callback=None):
        super().__init__(parent)
        self.instance = instance

        self._view: FunctionsView = parent
        self._table_view: QFunctionTableView
        self._filter_box: QFunctionTableFilterBox
        self._toolbar: FunctionTableToolbar
        self._status_label: QLabel

        self._last_known_func_addrs: Set[int] = set()
        self._function_count = None

        self._init_widgets(selection_callback)

    @property
    def show_alignment_functions(self):
        return self._table_view.show_alignment_functions

    @property
    def function_manager(self) -> Optional["FunctionManager"]:
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
        self._last_known_func_addrs = {func.addr for func in self._table_view._model.func_list}
        self.filter_functions(self._filter_box.text())
        self.update_displayed_function_count()

    #
    # Public methods
    #

    def refresh(self):
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

    def show_filter_box(self, prefix=""):
        if prefix:
            self._filter_box.setText(prefix)
        self._filter_box.show()
        self._filter_box.setFocus()

    def clear_filter_box(self):
        self._filter_box.setText("")
        self._table_view.setFocus()

    def toggle_show_alignment_functions(self):
        self._table_view.show_alignment_functions = not self._table_view.show_alignment_functions
        self._table_view.load_functions()
        self.update_displayed_function_count()

    def subscribe_func_select(self, callback):
        self._table_view.subscribe_func_select(callback)

    def update_displayed_function_count(self):
        cnt = self._table_view.model().rowCount()
        if self.function_manager is None:
            self._status_label.setText("")
            return
        if cnt == len(self.function_manager):
            self._status_label.setText("%d functions" % cnt)
        else:
            self._status_label.setText("%d/%d functions" % (cnt, len(self.function_manager)))

    def filter_functions(self, text):
        self._table_view.filter(text)
        self.update_displayed_function_count()

    #
    # Private methods
    #

    def _init_widgets(self, selection_callback=None):
        # function table view
        self._table_view = QFunctionTableView(self, self._view.workspace, self.instance, selection_callback)

        # filter text box
        self._filter_box = QFunctionTableFilterBox(self)
        self._filter_box.setClearButtonEnabled(True)
        self._filter_box.addAction(
            qta.icon("fa5s.search", color=Conf.palette_placeholdertext), QLineEdit.LeadingPosition
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

    def _updated_functions(self, function_manager: "FunctionManager") -> Tuple[Set[int], Set[int]]:
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

    def _on_filter_box_text_changed(self, text):
        self.filter_functions(text)

    def _on_filter_box_return_pressed(self):
        self._table_view.jump_to_result()
        self.clear_filter_box()
