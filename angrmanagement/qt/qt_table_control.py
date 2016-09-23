""" Enaml widget for displaying and editing multi-column data items
"""

# -------------------------------------------------------------------------------
#  Imports:
# -------------------------------------------------------------------------------
from atom.api import Bool, Callable, Event, List, observe, set_default, Int, Value

from enaml.widgets.api import RawWidget
from enaml.core.declarative import d_
from enaml.qt.QtGui import QTableWidget, QTableWidgetItem, QAbstractItemView
from enaml.qt.QtCore import *

from angrmanagement.ui.notify import notify_update


class QtTableControl(RawWidget):
    """ A Qt4 implementation of an Enaml ProxyTableView.

    """

    __slots__ = '__weakref__'

    #: The list of str being viewed
    items = d_(List())

    #: The index of the currently selected str
    selected_index = d_(Int(-1))

    #: The currently selected str
    selected_item = d_(Value())

    #: selection event
    on_selected = d_(Event(), writable=False)

    #: Whether or not the items should be checkable
    checkable = d_(Bool(False))

    hug_width = set_default('weak')

    column_count = d_(Int(1))

    header_labels = d_(List())

    def _to_items(self, obj):
        """
        Convert a data model to a list of QTableWidgetItem objects that will be displayed in a row

        :param obj: The object to convert
        :return: A list of the converted QTableWidgetItem instance
        :rtype: list
        """

        raise NotImplementedError()

    # --------------------------------------------------------------------------
    # Initialization API
    # --------------------------------------------------------------------------
    def create_widget(self, parent):
        """ Create the QTableView widget.

        """
        # Create the list model and accompanying controls:
        widget = QTableWidget(parent)

        widget.setColumnCount(self.column_count)
        widget.setSelectionBehavior(QAbstractItemView.SelectRows)

        widget.setHorizontalHeaderLabels(self.header_labels)

        for item in self.items:
            self.add_item(widget, item)

        widget.itemSelectionChanged.connect(self.on_selection)

        # set selected_item here so that first change fires an 'update' rather than 'create' event
        self.selected_item = None

        return widget

    def add_item(self, widget, item):
        """

        :param QTableWidget widget: The QTableWidget widget
        :param item:
        :return:
        """

        itemWidget = self._to_items(item)
        #if self.checkable:
        #    itemWidget.setCheckState(Qt.Checked)
        # widget.addItem(itemWidget)

    # --------------------------------------------------------------------------
    # Signal Handlers
    # --------------------------------------------------------------------------
    def on_selection(self):
        """ The signal handler for the index changed signal.

        """
        widget = self.get_widget()
        self.selected_index = widget.currentRow()
        if 0 <= self.selected_index < len(self.items):
            self.selected_item = self.items[self.selected_index]
        else:
            self.selected_item = None
            self.selected_index = -1
        # notify_update(self, 'selected_item')
        self.on_selected(self.selected_item)

    # --------------------------------------------------------------------------
    # QtTableControl API
    # --------------------------------------------------------------------------

    def set_items(self, items, widget=None):
        widget = self.get_widget()  # type: QTableWidget
        items_count = len(items)

        widget.setRowCount(items_count)

        for idx, item in enumerate(items):
            # Convert it to a item list
            converted = self._to_items(item)
            for i, it in enumerate(converted):
                widget.setItem(idx, i, it)

        if 0 <= self.selected_index < len(self.items):
            self.selected_item = self.items[self.selected_index]
        else:
            self.selected_item = None
            self.selected_index = -1

    def refresh_items(self):
        self.set_items(self.items)
        self.on_selected(self.selected_item)

    # --------------------------------------------------------------------------
    # Observers
    # --------------------------------------------------------------------------
    # @observe('items', 'operations')
    @observe('items')
    def _update_proxy(self, change):
        """ An observer which sends state change to the proxy.

        """
        # The superclass handler implementation is sufficient.
        if self.get_widget() is not None and change['name'] == 'items':
            self.set_items(self.items)


# Helper methods
def _set_item_flag(item, flag, enabled):
    """ Set or unset the given item flag for the item.

    """
    flags = item.flags()
    if enabled:
        flags |= flag
    else:
        flags &= ~flag
    item.setFlags(flags)
