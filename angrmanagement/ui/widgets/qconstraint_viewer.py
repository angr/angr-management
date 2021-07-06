from PySide2.QtWidgets import QFrame, QHeaderView, QSizePolicy, QVBoxLayout,QTableWidget, QTableWidgetItem


class QConstraintViewer(QFrame):
    """
    `QConstraintViewer` in `StateInspector`
    """
    COLUMNS = [ "Constraint", "Cardinality", "Depth", "# Variables" ]

    def __init__(self, state, parent, workspace):
        super().__init__(parent)

        self._state = state
        self.workspace = workspace

        self.table = None

        self._state.am_subscribe(self._watch_state)

    #
    # Public methods
    #

    def reload(self):
        if self._state.am_none:
            return

        self.table.setRowCount(0)
        for constraint in self._state.solver.constraints:
            count = self.table.rowCount()
            self.table.insertRow(count)
            self.table.setItem(count, 0, QTableWidgetItem(constraint.shallow_repr()))
            self.table.setItem(count, 1, QTableWidgetItem(str(constraint.cardinality)))
            self.table.setItem(count, 2, QTableWidgetItem(str(constraint.depth)))
            self.table.setItem(count, 3, QTableWidgetItem(str(len(list(constraint.recursive_leaf_asts)))))

    #
    # Private methods
    #

    def _init_widgets(self):
        if self._state.am_none:
            return

        layout = QVBoxLayout()

        table = QTableWidget(self)
        table.setColumnCount(len(self.COLUMNS))
        table.setHorizontalHeaderLabels(self.COLUMNS)
        table.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.Expanding)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
        table.horizontalHeader().setSectionResizeMode(0,QHeaderView.Stretch)

        self.table = table
        layout.addWidget(table)

        self.setLayout(layout)


    def _watch_state(self, **kwargs):  #pylint: disable=unused-argument
        if self.table is None:
            self._init_widgets()
        self.reload()
