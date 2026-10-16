from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QAction, QCursor, QPalette
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.data.annotations import CommentKind
from angrmanagement.present.functions import (
    TAG_STRS,
    FunctionsPresenter,
    FunctionTableEntry,
    FunctionTableModel,
    function_context_menu,
)
from angrmanagement.ui.dialogs.set_comment import SetComment
from angrmanagement.ui.icons import icon
from angrmanagement.ui.toolbars import FunctionTableToolbar
from angrmanagement.ui.widgets.qfast_table_view import QFastTableView
from angrmanagement.ui.widgets.qt_table import QtTableModelAdapter

if TYPE_CHECKING:
    import PySide6
    import PySide6.QtCore
    import PySide6.QtGui
    from angr.knowledge_plugins.functions import Function, FunctionManager

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.views.functions_view import FunctionsView
    from angrmanagement.ui.workspace import Workspace

__all__ = [
    "FunctionTableEntry",
    "QFunctionTable",
    "QFunctionTableFilterBox",
    "QFunctionTableHeaderView",
    "QFunctionTableModel",
    "QFunctionTableView",
]


class QFunctionTableModel(QtTableModelAdapter):
    """
    The table model for QFunctionTable: a Qt model over a
    :class:`~angrmanagement.present.functions.FunctionTableModel`, which holds the rows, the filter and the sorting.
    """

    Headers = FunctionTableModel.Headers
    INLINE_COL = FunctionTableModel.INLINE_COL
    NAME_COL = FunctionTableModel.NAME_COL
    TAGS_COL = FunctionTableModel.TAGS_COL
    ADDRESS_COL = FunctionTableModel.ADDRESS_COL
    BINARY_COL = FunctionTableModel.BINARY_COL
    SIZE_COL = FunctionTableModel.SIZE_COL
    BLOCKS_COL = FunctionTableModel.BLOCKS_COL
    COMPLEXITY_COL = FunctionTableModel.COMPLEXITY_COL
    TAG_STRS = TAG_STRS

    table_model: FunctionTableModel

    def __init__(
        self,
        workspace: Workspace,
        instance: Instance,
        table_view: QFunctionTableView | None = None,
        func_list=None,
        table_model: FunctionTableModel | None = None,
    ) -> None:
        super().__init__(table_model if table_model is not None else FunctionTableModel(workspace, instance))
        self.workspace = workspace
        self.instance = instance
        self.table_view = table_view
        if func_list:
            self.table_model.set_rows(func_list)

    def __len__(self) -> int:
        return self.table_model.row_count

    @property
    def func_list(self) -> list[FunctionTableEntry]:
        return self.table_model.rows

    @func_list.setter
    def func_list(self, v) -> None:
        self.table_model.set_rows(v or [])

    def filter(self, keyword, show_alignment: bool = True) -> None:
        if show_alignment != self.table_model.show_alignment:
            self.table_model.set_show_alignment(show_alignment)
        self.table_model.filter(keyword)

    def totalCount(self) -> int:
        return self.table_model.total_count


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

    def __init__(
        self,
        parent,
        workspace: Workspace,
        instance: Instance,
        selection_callback=None,
        presenter: FunctionsPresenter | None = None,
    ) -> None:
        header = QFunctionTableHeaderView(Qt.Orientation.Horizontal)
        super().__init__(parent, header=header)
        self.workspace = workspace
        self.instance = instance
        self.presenter = presenter if presenter is not None else FunctionsPresenter(workspace, instance)
        # the context menu last shown; the QMenu has no other owner while it is open
        self._context_qmenu = None

        self._function_table: QFunctionTable = parent
        # choosing a function goes through the presenter, which also tells the workspace
        if selection_callback is not None:
            self.presenter.subscribe_func_select(selection_callback)

        header.setSectionsClickable(True)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        header.setSortIndicatorShown(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        self.set_row_height(24)

        self.filter_text = ""
        self._model = QFunctionTableModel(self.workspace, self.instance, self, table_model=self.presenter.model)

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

    @property
    def show_alignment_functions(self) -> bool:
        return self.presenter.show_alignment_functions

    @show_alignment_functions.setter
    def show_alignment_functions(self, show: bool) -> None:
        self.presenter.model.set_show_alignment(show)

    def refresh(self, added_funcs: set[int] | None = None, removed_funcs: set[int] | None = None) -> None:
        if added_funcs or removed_funcs:
            self.presenter.model.update(added_funcs or (), removed_funcs or ())
        self.viewport_update()

    def changeEvent(self, event):  # type: ignore
        if event.type() == QEvent.Type.PaletteChange:
            self._model.clear_data_cache()
        super().changeEvent(event)

    @property
    def function_manager(self):
        return self.presenter.function_manager

    @function_manager.setter
    def function_manager(self, functions) -> None:
        self.presenter.set_function_manager(functions)

    def subscribe_func_select(self, callback) -> None:
        self.presenter.subscribe_func_select(callback)

    def filter(self, keyword, show_alignment: bool = True) -> None:
        self.filter_text = keyword
        self._model.filter(keyword, show_alignment=show_alignment)

    def jump_to_result(self, index: int = 0) -> None:
        self.presenter.jump_to_result(index)

    def load_functions(self) -> None:
        """
        Load all functions from FunctionManager and create table entries for them.
        """
        self.presenter.model.load(self.presenter.function_manager)

    def _on_function_selected_row(self, row: int) -> None:
        self.presenter.model.activate(row)

    def _on_key_pressed(self, text: str) -> None:
        # show the filtering text box
        self._function_table.show_filter_box(prefix=text)

    def _on_context_menu_requested(self, global_pos: PySide6.QtCore.QPoint) -> None:
        funcs = self.presenter.model.functions(self.selected_rows())
        menu = function_context_menu(self.workspace, funcs, edit_comment=self._edit_function_comment)
        if menu is None:
            return
        menu.parent = self
        self._context_qmenu = menu.qmenu(cached=False)
        self._context_qmenu.popup(global_pos)

    def _edit_function_comment(self, func: Function) -> None:
        self.workspace.main_instance.annotations.set_kind(func.addr, CommentKind.FUNCTION)
        SetComment(self.workspace, func.addr, parent=self).exec_()


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

    def __init__(
        self, parent, instance: Instance, selection_callback=None, presenter: FunctionsPresenter | None = None
    ) -> None:
        super().__init__(parent)
        self.instance = instance

        self._view: FunctionsView = parent
        self._table_view: QFunctionTableView
        self._filter_box: QFunctionTableFilterBox
        self._toolbar: FunctionTableToolbar
        self._status_label: QLabel

        self.presenter = presenter if presenter is not None else FunctionsPresenter(self._view.workspace, instance)

        self._init_widgets(selection_callback)
        self.presenter.model.changed.connect(self._on_model_changed)

    @property
    def show_alignment_functions(self):
        return self._table_view.show_alignment_functions

    @property
    def function_manager(self) -> FunctionManager | None:
        return self.presenter.function_manager

    @function_manager.setter
    def function_manager(self, v):
        self.presenter.set_function_manager(v)
        self.filter_functions(self._filter_box.text())
        self.update_displayed_function_count()

    #
    # Public methods
    #

    def refresh(self) -> None:
        if self.function_manager is None:
            return
        self.presenter.refresh()
        self._table_view.viewport_update()
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
        self.presenter.toggle_show_alignment_functions()
        self.update_displayed_function_count()

    def subscribe_func_select(self, callback) -> None:
        self._table_view.subscribe_func_select(callback)

    def update_displayed_function_count(self) -> None:
        self._status_label.setText(self.presenter.count_text())

    def filter_functions(self, text: str) -> None:
        self._table_view.filter(text, show_alignment=self._table_view.show_alignment_functions)
        self.update_displayed_function_count()

    #
    # Private methods
    #

    def _init_widgets(self, selection_callback=None) -> None:
        # function table view
        self._table_view = QFunctionTableView(
            self, self._view.workspace, self.instance, selection_callback, presenter=self.presenter
        )

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

    #
    # Events
    #

    def _on_model_changed(self, *_args) -> None:
        self._table_view.viewport_update()
        self.update_displayed_function_count()

    def _on_filter_box_text_changed(self, text: str) -> None:
        self.filter_functions(text)

    def _on_filter_box_return_pressed(self) -> None:
        self._table_view.jump_to_result()
        self.clear_filter_box()
