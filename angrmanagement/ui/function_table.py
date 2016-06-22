
from enaml.qt.QtGui import QTableWidgetItem, QColor
from enaml.qt.QtCore import Qt

from .tablecontrol import QtTableControl

class FunctionTableControl(QtTableControl):
    def _to_items(self, function):
        """

        :param angr.knowledge.Function function: The Function object.
        :return: a list of QTableWidgetItem objects
        :rtype: list
        """

        name = function.name
        address = function.addr
        blocks = len(list(function.blocks))
        size = "Unknown"

        widgets = [
            QTableWidgetItem(name),
            QTableWidgetItem("%x" % address),
            QTableWidgetItem(size),
            QTableWidgetItem("%d" % blocks),
        ]

        color = QColor(0, 0, 0)
        if function.is_syscall:
            color = QColor(0, 0, 0x80)
        elif function.is_plt:
            color = QColor(0, 0x80, 0)
        elif function.is_simprocedure:
            color = QColor(0x80, 0, 0)

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)
            w.setForeground(color)

        return widgets
