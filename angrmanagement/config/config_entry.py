from __future__ import annotations

from typing import Any

from angrmanagement.data.object_container import EventSentinel
from angrmanagement.logic.signal import Signal

from .color import Color
from .font import FontSpec, FontStyle, FontWeight


class ConfigurationEntryValue(EventSentinel):
    """
    An object container that both calls am_event() and emits 'changed' on an update
    This object allows usage of both types of event triggers
    """

    def __init__(self, value) -> None:
        super().__init__()
        self._value = value
        self.changed = Signal(object, name="changed")

    def get(self):
        return self._value

    def set(self, value) -> None:
        """
        Set the value, if it changes, trigger events
        """
        if value != self._value:
            self._value = value
            self.am_event()
            self.changed.emit(value)


def _make_config_entry_value(init_value, type_):  # pylint:disable=unused-argument
    return ConfigurationEntryValue(init_value)


def _neutral_type_and_value(type_, value) -> tuple[Any, Any]:
    """
    Translate an entry declared with a Qt type (as plugins written for the Qt frontend do) to the neutral type.

    Qt types are recognised by name, so this module never imports Qt.
    """
    qualname = getattr(type_, "__qualname__", None)
    if qualname == "QColor":
        if type(value).__name__ == "QColor":
            value = Color.from_qcolor(value)
        return Color, value
    if qualname == "QFont":
        if type(value).__name__ == "QFont":
            value = FontSpec.from_qfont(value)
        return FontSpec, value
    if qualname == "QFont.Weight":
        if value is not None and not isinstance(value, str):
            value = FontWeight(int(getattr(value, "value", value)))
        return FontWeight, value
    if qualname == "QFont.Style":
        if value is not None and not isinstance(value, str):
            value = FontStyle(int(getattr(value, "value", value)))
        return FontStyle, value
    return type_, value


class ConfigurationEntry:
    """
    Describes a configuration entry in angr management.
    """

    __slots__ = ("name", "type_", "_value", "default_value")

    def __init__(self, name: str, type_, value, default_value=None) -> None:
        declared_type = type_
        type_, value = _neutral_type_and_value(declared_type, value)
        if default_value is not None:
            _, default_value = _neutral_type_and_value(declared_type, default_value)
        self.name = name
        self.type_ = type_
        self._value = _make_config_entry_value(value, self.type_)
        self.default_value = value if default_value is None and value is not None else default_value

    def copy(self):
        """
        Copies over data, does *not* copy subscribers, signal connections, or slot connections
        """
        return ConfigurationEntry(self.name, self.type_, self.value, default_value=self.default_value)

    @property
    def value(self):
        return self._value.get()

    @value.setter
    def value(self, new) -> None:
        self._value.set(new)

    #
    # Event functions
    #

    @property
    def changed(self) -> Signal:
        """A signal emitted with the new value whenever the value changes."""
        return self._value.changed

    def subscribe(self, listener) -> None:
        self._value.am_subscribe(listener)

    def unsubscribe(self, listener) -> None:
        self._value.am_unsubscribe(listener)
