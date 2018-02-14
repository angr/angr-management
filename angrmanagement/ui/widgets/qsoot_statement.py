
from PySide.QtGui import QColor
from PySide.QtCore import Qt

from .qgraph_object import QGraphObject
from .qsoot_expression import QSootExpression

from angr.analyses.disassembly import SootExpression, SootExpressionTarget, SootExpressionInvoke, \
    SootExpressionStaticFieldRef


class QSootStatement(QGraphObject):

    ADDR_SPACING = 20
    COMPONENT_SPACING = 5

    def __init__(self, workspace, func_addr, disasm_view, disasm, infodock, stmt, config):
        super(QSootStatement, self).__init__()

        self.workspace = workspace
        self.func_addr = func_addr
        self.infodock = infodock
        self.stmt = stmt
        self.disasm_view = disasm_view
        self.disasm = disasm

        self._config = config

        self._addr = None
        self._addr_width = None
        self._components = [ ]

        self._init_widgets()

    def paint(self, painter):
        """

        :param QPainter painter:
        :return:
        """

        x = self.x
        y = self.y

        # address
        if self.disasm_view.show_address:
            painter.setPen(Qt.black)
            painter.drawText(x, y + self._config.disasm_font_ascent, self._addr)

            x += self._addr_width + self.ADDR_SPACING

        # components
        painter.setPen(QColor(0, 0, 0x80))
        for component in self._components:
            if type(component) is str:
                painter.drawText(x, y + self._config.disasm_font_ascent, component)
                x += len(component) * self._config.disasm_font_width
            else:
                component.x = x
                component.y = y
                component.paint(painter)
                x += component.width

            x += self.COMPONENT_SPACING

    def refresh(self):
        super(QSootStatement, self).refresh()

        for component in self._components:
            if not type(component) is str:
                component.refresh()

        self._update_size()

    def select(self):
        pass

    def unselect(self):
        pass

    def toggle_select(self):
        pass

    def select_component(self, component_idx):
        pass

    def unselect_component(self, component_idx):
        pass

    def get_component(self, component_idx):
        pass

    #
    # Event handlers
    #

    #
    # Private methods
    #

    def _init_widgets(self):

        self._addr = "%s" % self.stmt.stmt_idx
        self._addr_width = self._config.disasm_font_width * len(self._addr)

        expr_id = 0

        for i, component in enumerate(self.stmt.components):
            if isinstance(component, SootExpression):

                branch_type = None
                if isinstance(component, SootExpressionTarget):
                    # Local target
                    branch_type = 'local'
                elif isinstance(component, SootExpressionInvoke):
                    # Invoke a function
                    branch_type = 'function'

                field_ref = False
                if isinstance(component, SootExpressionStaticFieldRef):
                    field_ref = True

                expr = QSootExpression(self.workspace, self.func_addr, self.disasm_view, self.disasm, self.infodock,
                                       self.stmt, component, expr_id, branch_type, field_ref, self._config
                                       )
                expr_id += 1
                self._components.append(expr)
            else:
                self._components.append(component)

        self._update_size()

    def _update_size(self):

        self._height = self._config.disasm_font_height
        self._width = 0

        if self.disasm_view.show_address:
            self._width += self._addr_width + self.ADDR_SPACING

        for component in self._components:
            if type(component) is str:
                self._width += len(component) * self._config.disasm_font_width
            else:
                self._width += component.width
            self._width += self.COMPONENT_SPACING

        #if self._string is not None:
        #    self._width += self.STRING_SPACING + self._string_width
