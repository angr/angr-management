
from atom.api import Event, Typed

from enaml.core.declarative import d_
from enaml.widgets.container import ProxyContainer, Container


class ProxyRichContainer(ProxyContainer):
    pass


class RichContainer(Container):

    clicked = d_(Event())

    right_clicked = d_(Event())

    key_pressed = d_(Event())

    proxy = Typed(ProxyRichContainer)
