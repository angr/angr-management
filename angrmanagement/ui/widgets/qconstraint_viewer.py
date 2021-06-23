import angr
import claripy

from PySide2.QtWidgets import QFrame, QHeaderView, QSizePolicy, QVBoxLayout,QTableWidget, QTableWidgetItem


class SrcAddrAnnotation(claripy.Annotation):
    def __init__(self, addr):
        self.addr = addr

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return True

    def relocate(self, src, dst):
        return self


def attach_addr_annotation(state):
    for i in range(len(state.solver.constraints)):
        if SrcAddrAnnotation not in [type(a) for a in state.solver.constraints[i].annotations]:
            state.solver.constraints[i] = \
                    state.solver.constraints[i].annotate(SrcAddrAnnotation(state.addr))
    return state

class QConstraintViewer(QFrame):

    COLUMNS = [ "Constraint", "Src Addr", "Cardinality", "Depth", "# Variables" ]

    def __init__(self, state, parent, workspace):
        super().__init__(parent)

        self._state = state
        self.workspace = workspace

        self.table = None

        self._state.am_subscribe(self._watch_state)
        self.workspace.instance.states.am_subscribe(self._insert_inspect_hook)

    #
    # Public methods
    #

    def reload(self):
        self.table.setRowCount(0)
        for constraint in self._state.solver.constraints:
            count = self.table.rowCount()
            self.table.insertRow(count)
            self.table.setItem(count, 0, QTableWidgetItem(constraint.shallow_repr()))

            src_addr = next(a for a in constraint.annotations if isinstance(a, SrcAddrAnnotation)).addr

            self.table.setItem(count, 1, QTableWidgetItem(hex(src_addr)))
            self.table.setItem(count, 2, QTableWidgetItem(str(constraint.cardinality)))
            self.table.setItem(count, 3, QTableWidgetItem(str(constraint.depth)))
            self.table.setItem(count, 4, QTableWidgetItem(str(len(list(constraint.recursive_leaf_asts)))))

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

    @staticmethod
    def _insert_inspect_hook(**kwargs):
        if kwargs.get("src","")  == "new":
            state = kwargs.get("state")
            state.inspect.b(event_type='constraints', when=angr.BP_AFTER, action=attach_addr_annotation)
