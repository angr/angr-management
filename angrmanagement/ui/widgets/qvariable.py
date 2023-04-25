from PySide6.QtCore import QRectF, Qt
from PySide6.QtWidgets import QGraphicsSimpleTextItem

from .qgraph_object import QCachedGraphicsItem


class QVariable(QCachedGraphicsItem):
    IDENT_LEFT_PADDING = 5
    OFFSET_LEFT_PADDING = 12

    def __init__(self, instance, disasm_view, variable, config, parent=None):
        super().__init__(parent=parent)

        # initialization
        self.instance = instance
        self.disasm_view = disasm_view
        self.variable = variable
        self._config = config

        self._variable_name = None
        self._variable_name_item: QGraphicsSimpleTextItem = None
        self._variable_ident = None
        self._variable_ident_item: QGraphicsSimpleTextItem = None
        self._variable_offset = None
        self._variable_offset_item: QGraphicsSimpleTextItem = None

        self._init_widgets()

    #
    # Public methods
    #

    def paint(self, painter, option, widget):  # pylint: disable=unused-argument
        pass

    def refresh(self):
        super().refresh()

        if self._variable_ident_item is not None:
            self._variable_ident_item.setVisible(self.disasm_view.show_variable_identifier)

        self._layout_items_and_update_size()

    #
    # Private methods
    #

    def _init_widgets(self):
        # variable name
        self._variable_name = "" if not self.variable.name else self.variable.name
        self._variable_name_item = QGraphicsSimpleTextItem(self._variable_name, self)
        self._variable_name_item.setFont(self._config.disasm_font)
        self._variable_name_item.setBrush(Qt.darkGreen)  # TODO: Expose it as a configuration entry in Config

        # variable ident
        self._variable_ident = "<%s>" % ("" if not self.variable.ident else self.variable.ident)
        self._variable_ident_item = QGraphicsSimpleTextItem(self._variable_ident, self)
        self._variable_ident_item.setFont(self._config.disasm_font)
        self._variable_ident_item.setBrush(Qt.blue)  # TODO: Expose it as a configuration entry in Config
        self._variable_ident_item.setVisible(self.disasm_view.show_variable_identifier)

        # variable offset
        self._variable_offset = "%#x" % self.variable.offset
        self._variable_offset_item = QGraphicsSimpleTextItem(self._variable_offset, self)
        self._variable_offset_item.setFont(self._config.disasm_font)
        self._variable_offset_item.setBrush(Qt.darkYellow)  # TODO: Expose it as a configuration entry in Config

        self._layout_items_and_update_size()

    def _layout_items_and_update_size(self):
        x, y = 0, 0

        # variable name
        self._variable_name_item.setPos(x, y)
        x += self._variable_name_item.boundingRect().width() + self.IDENT_LEFT_PADDING

        if self.disasm_view.show_variable_identifier:
            # identifier
            x += self.IDENT_LEFT_PADDING
            self._variable_ident_item.setPos(x, y)
            x += self._variable_ident_item.boundingRect().width()

        # variable offset
        x += self.OFFSET_LEFT_PADDING
        self._variable_offset_item.setPos(x, y)
        x += self._variable_offset_item.boundingRect().width()

        self._width = x
        self._height = self._variable_name_item.boundingRect().height()
        self.recalculate_size()

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
