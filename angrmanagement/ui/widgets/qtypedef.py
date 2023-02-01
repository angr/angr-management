from typing import TYPE_CHECKING

from angr.sim_type import SimStruct, SimTypeBottom, SimUnion, TypeRef
from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QBrush, QColor, QPainter
from PySide6.QtWidgets import QMessageBox, QSizePolicy, QWidget

from angrmanagement.config import Conf
from angrmanagement.ui.dialogs.type_editor import CTypeEditor, edit_field

if TYPE_CHECKING:
    from angr.knowledge_plugins.types import TypesStore

LINE_HEIGHT = 20
COL_WIDTH = 8


class QCTypeDef(QWidget):
    """
    A widget to display a C SimType.
    """

    def __init__(self, parent, ty: TypeRef, all_types: "TypesStore"):
        super().__init__(parent)

        self.type = ty
        self.text = ""  # this will be used for full-text search
        self.lines = [""]
        self.highlight = None  # which line should be highlighted
        self.all_types = all_types

        self.setAttribute(Qt.WA_Hover)
        self.setMouseTracking(True)

        self.refresh()

    def refresh(self):
        if self.type._arch is None:
            raise TypeError("Must provide SimTypes with arches to QTypeDef")

        self.text = f"typedef {self.type.type.c_repr(name=self.type.name, full=1)};"
        self.lines = self.text.split("\n")
        fields = None
        offsets = None
        for i, line in enumerate(self.lines):
            type_size = self.type.size if not isinstance(self.type.type, SimTypeBottom) else 0
            if i == 0:
                prefix = f"{type_size // self.type._arch.byte_width:08x}"
            elif isinstance(self.type.type, SimUnion):
                prefix = "00000000"
            elif isinstance(self.type.type, SimStruct):
                fieldno = i - 1
                if fields is None:
                    fields = list(self.type.type.fields)
                    offsets = self.type.type.offsets
                if fieldno < len(fields):
                    prefix = f"{offsets[fields[fieldno]]:08x}"
                else:
                    prefix = f"{type_size // self.type._arch.byte_width:08x}"
            else:
                raise TypeError("I don't know why a %s renders with more than one line" % type(self.type.type))

            self.lines[i] = f"{prefix}  {line}"

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        height = len(self.lines) * LINE_HEIGHT + LINE_HEIGHT // 2
        self.setMinimumHeight(height)
        self.setMaximumHeight(height)
        self.setMinimumWidth(max(len(line) for line in self.lines) * COL_WIDTH)

        self.repaint()

    def sizeHint(self):
        return QSize(self.minimumWidth(), self.minimumHeight())

    def leaveEvent(self, event):  # pylint: disable=unused-argument
        self.highlight = None

    def mouseMoveEvent(self, event):
        old_highlight = self.highlight
        self.highlight = min(max((event.pos().y() - 5) // LINE_HEIGHT, 0), len(self.lines) - 1)
        if old_highlight != self.highlight:
            self.repaint()

    def paintEvent(self, event):  # pylint: disable=unused-argument
        painter = QPainter(self)

        if self.highlight is not None:
            # TODO use config colors
            painter.fillRect(0, 5 + 20 * self.highlight, self.width(), 20, QBrush(QColor(0xC0, 0xC0, 0xC0, 0xFF)))

        painter.setFont(Conf.disasm_font)
        y = 20
        for line in self.lines:
            painter.drawText(0, y, line)
            y += 20

    def mouseDoubleClickEvent(self, event):  # pylint: disable=unused-argument
        if self.highlight is None:
            return

        if self.highlight != 0:
            fieldno = self.highlight - 1
            try:
                edited = edit_field(self.type.type, fieldno)
            except IndexError:
                pass
            else:
                if edited:
                    self.refresh()
                return

        dialog = CTypeEditor(
            None, self.type._arch, self.text, multiline=True, allow_multiple=False, predefined_types=self.all_types
        )
        dialog.exec_()
        if dialog.result:
            name, ty = dialog.result[0]
            if name is not None and name != self.type.name:
                if name in self.all_types:
                    QMessageBox.warning(None, "Duplicate type name", f"The name {name} is already taken.")
                else:
                    self.all_types.rename(self.type.name, name)
            self.type.type = ty
            self.refresh()
