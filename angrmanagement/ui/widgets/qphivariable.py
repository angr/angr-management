from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QRectF, Qt

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from PySide6.QtGui import QPainter
    from PySide6.QtWidgets import QStyleOptionGraphicsItem, QWidget

    from angrmanagement.data.instance import Instance


class QPhiVariable(QCachedGraphicsItem):
    """QPhiVariable is a graphical representation of a phi variable in the disassembly view."""

    IDENT_LEFT_PADDING = 5

    def __init__(self, instance: Instance, disasm_view, phi_variable, config, parent=None) -> None:
        """

        :param workspace:
        :param disasm_view:
        :param PhiVariable phi_variable:
        :param config:
        """

        super().__init__(parent=parent)

        # initialization
        self.instance = instance
        self.disasm_view = disasm_view
        self.phi = phi_variable.variable  # the major variable
        self.variables = phi_variable.variables  # the sub variables
        self._config = config

        self._variable_name = None
        self._variable_name_width = None
        self._variable_ident = None
        self._variable_ident_width = None

        self._subvar_names = None
        self._subvar_name_widths = None
        self._subvar_idents = None
        self._subvar_ident_widths = None

        self._width = 0
        self._height = 0

        self._init_widgets()

    #
    # Public methods
    #

    def paint(  # pylint: disable=unused-argument
        self,
        painter: QPainter,
        option: QStyleOptionGraphicsItem,
        widget: QWidget | None = None,
    ) -> None:
        if self.disasm_view.show_variable_identifier is False:
            # Phi variables are not displayed if variable identifies are hidden
            return

        x = 0

        painter.setFont(self._config.disasm_font)

        # variable name
        painter.setPen(Qt.GlobalColor.darkGreen)
        painter.drawText(x, self._config.disasm_font_ascent, self._variable_name)
        x += self._variable_name_width

        # variable ident
        if self.disasm_view.show_variable_identifier:
            x += self.IDENT_LEFT_PADDING
            painter.setPen(Qt.GlobalColor.blue)
            painter.drawText(x, self._config.disasm_font_ascent, self._variable_ident)
            x += self._variable_ident_width

        # The equal sign
        painter.setPen(Qt.GlobalColor.black)
        painter.drawText(x, self._config.disasm_font_ascent, " = ")
        x += self._config.disasm_font_width * 3
        painter.setPen(Qt.GlobalColor.darkGreen)
        painter.drawText(x, self._config.disasm_font_ascent, "\u0278(")
        x += self._config.disasm_font_width * 2

        for i, (subvar_ident, ident_width) in enumerate(
            zip(self._subvar_idents, self._subvar_ident_widths, strict=False)
        ):
            painter.setPen(Qt.GlobalColor.darkGreen)
            painter.drawText(x, self._config.disasm_font_ascent, subvar_ident)
            x += ident_width
            if i != len(self._subvar_idents) - 1:
                painter.setPen(Qt.GlobalColor.black)
                painter.drawText(x, self._config.disasm_font_ascent, ", ")
                x += 2 + self._config.disasm_font_width

        painter.setPen(Qt.GlobalColor.darkGreen)
        painter.drawText(x, self._config.disasm_font_ascent, ")")

    def refresh(self) -> None:
        super().refresh()

        self._update_size()

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        # variable name
        self._variable_name = "{%s}" % ("Unk" if not self.phi.name else self.phi.name)
        # variable ident
        self._variable_ident = "<%s>" % ("Unk" if not self.phi.ident else self.phi.ident)

        # subvariables
        self._subvar_names = []
        self._subvar_idents = []
        for subvar in self.variables:
            name = "Unk" if not subvar.name else subvar.name
            self._subvar_names.append(name)
            ident = "<%s>" % ("Unk" if not subvar.ident else subvar.ident)
            self._subvar_idents.append(ident)

        self._update_size()

    def _update_size(self) -> None:
        if self.disasm_view.show_variable_identifier is False:
            # Phi variables are not displayed if variable identifies are hidden
            self._width = 0
            self._height = 0
            return

        self._variable_name_width = len(self._variable_name) * self._config.disasm_font_width
        self._variable_ident_width = len(self._variable_ident) * self._config.disasm_font_width

        # Update widths of sub-variables
        self._subvar_name_widths = []
        for name in self._subvar_names:
            self._subvar_name_widths.append(len(name) * self._config.disasm_font_width)
        self._subvar_ident_widths = []
        for ident in self._subvar_idents:
            self._subvar_ident_widths.append(len(ident) * self._config.disasm_font_width)

        self._width = (
            self._variable_name_width
            + self._config.disasm_font_width * 5
            + sum(self._subvar_ident_widths)  # " = ", the phi sign, and the "("
            + (len(self._subvar_ident_widths) - 1) * 2 * self._config.disasm_font_width
            + self._config.disasm_font_width * 1  # ")"
        )
        if self.disasm_view.show_variable_identifier:
            self._width += self.IDENT_LEFT_PADDING + self._variable_ident_width

        self._height = self._config.disasm_font_height

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
