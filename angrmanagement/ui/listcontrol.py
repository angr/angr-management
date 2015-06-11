""" Enaml widget for editing a list of string
"""

#-------------------------------------------------------------------------------
#  Imports:
#-------------------------------------------------------------------------------
from atom.api import Bool, Callable, Event, List, observe, set_default, Unicode, Enum, Int, Value

from enaml.widgets.api import RawWidget
from enaml.core.declarative import d_
from enaml.qt.QtGui import QListWidget, QListWidgetItem, QAbstractItemView
from enaml.qt.QtCore import *


class QtListControl(RawWidget):
    """ A Qt4 implementation of an Enaml ProxyListStrView.

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

    #: Converter from item to string
    to_string = d_(Callable(unicode))

    #: Whether or not the items should be checkable
    checkable = d_(Bool(False))

    #: List of operations the user can perform
    # operations = d_(List(Enum( 'delete', 'insert', 'append', 'edit', 'move' ),
    #                    [ 'delete', 'insert', 'append', 'edit', 'move' ] ))

    #: .
    hug_width = set_default('weak')
    
    #--------------------------------------------------------------------------
    # Initialization API
    #--------------------------------------------------------------------------
    def create_widget(self, parent):
        """ Create the QListView widget.

        """
        # Create the list model and accompanying controls:
        widget = QListWidget(parent)
        for item in self.items:
            self.add_item(widget, item)

        widget.itemSelectionChanged.connect(self.on_selection)

        # set selected_item here so that first change fires an 'update' rather than 'create' event
        self.selected_item = None
        
        return widget

    def add_item(self, widget, item):
        itemWidget = QListWidgetItem(self.to_string(item))
        if self.checkable:
            itemWidget.setCheckState(Qt.Checked)
        widget.addItem(itemWidget)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------
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
        self.on_selected(self.selected_item)

    #--------------------------------------------------------------------------
    # ProxyListStrView API
    #--------------------------------------------------------------------------

    def set_items(self, items, widget = None):
        """
        """
        widget = self.get_widget()
        count = widget.count()
        nitems = len(items)
        for idx, item in enumerate(items[:count]):
            itemWidget = widget.item(idx)
            itemWidget.setText(self.to_string(item))
        if nitems > count:
            for item in items[count:]:
                self.add_item(widget, item)
        elif nitems < count:
            for idx in reversed(xrange(nitems, count)):
                widget.takeItem(idx)
        if 0 <= self.selected_index < len(self.items):
            self.selected_item = self.items[self.selected_index]
        else:
            self.selected_item = None
            self.selected_index = -1

    def refresh_items(self):
        self.set_items(self.items)
        self.on_selected(self.selected_item)

    #--------------------------------------------------------------------------
    # Observers
    #--------------------------------------------------------------------------
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
