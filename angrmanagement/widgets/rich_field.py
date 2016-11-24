

from atom.api import Event, Typed, ForwardTyped

from enaml.core.declarative import d_
from enaml.widgets.field import ProxyField, Field


class ProxyRichField(ProxyField):

    declaration = ForwardTyped(lambda: RichField)


class RichField(Field):

    key_pressed = d_(Event())
