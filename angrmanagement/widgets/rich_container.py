
from atom.api import (
    Typed, ForwardTyped, Unicode, Enum, Event, observe, set_default
)

from enaml.core.declarative import d_
from enaml.widgets.container import ProxyContainer, Container


class ProxyRichContainer(ProxyContainer):
    pass


class RichContainer(Container):

    clicked = d_(Event())

    right_clicked = d_(Event())
