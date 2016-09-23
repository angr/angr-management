
from atom.api import (
    Typed, ForwardTyped, Unicode, Enum, Event, observe, set_default, Str
)

from enaml.core.declarative import d_
from enaml.widgets.control import Control, ProxyControl


class ProxyRichLabel(ProxyControl):
    """
    The abstract definition of a proxy Label object.
    """
    #: A reference to the Label declaration.
    declaration = ForwardTyped(lambda: RichLabel)

    def set_text(self, text):
        raise NotImplementedError

    def set_align(self, align):
        raise NotImplementedError

    def set_vertical_align(self, align):
        raise NotImplementedError


class RichLabel(Control):
    """
    A simple control for displaying read-only text.
    """
    #: The unicode text for the label.
    text = d_(Unicode())

    #: The horizontal alignment of the text in the widget area.
    align = d_(Enum('left', 'right', 'center', 'justify'))

    #: The vertical alignment of the text in the widget area.
    vertical_align = d_(Enum('center', 'top', 'bottom'))

    #: An event emitted when the user clicks a link in the label.
    #: The payload will be the link that was clicked.
    link_activated = d_(Event(), writable=False)

    #: Labels hug their width weakly by default.
    hug_width = set_default('weak')

    #: A reference to the ProxyLabel object.
    proxy = Typed(ProxyRichLabel)

    mouse_pressed = d_(Event())

    #
    # Observers
    #

    @observe('text', 'align', 'vertical_align', 'style_selector')
    def _update_proxy(self, change):
        """
        An observer which sends the state change to the proxy.
        """
        # The superclass implementation is sufficient.
        super(RichLabel, self)._update_proxy(change)
