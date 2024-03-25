from __future__ import annotations

import logging
import traceback

from angrmanagement.utils.namegen import NameGenerator

log = logging.getLogger(__name__)


class EventSentinel:
    def __init__(self, logging_permitted: bool = True) -> None:
        self.am_subscribers = []
        self.am_logging_permitted: bool = logging_permitted

    def am_subscribe(self, listener) -> None:
        if listener is not None:
            self.am_subscribers.append(listener)

    def am_unsubscribe(self, listener) -> None:
        if listener is not None:
            try:
                self.am_subscribers.remove(listener)
            except ValueError:
                if self.am_logging_permitted:
                    log.warning("Double-unsubscribe of %s from %s", listener, self)
                else:
                    print("Double-unsubscribe of listener")  # No f-string in case str uses logging
                    traceback.print_exc()

    def am_event(self, **kwargs) -> None:
        for listener in self.am_subscribers:
            try:
                listener(**kwargs)
            except Exception:  # pylint: disable=broad-except
                if self.am_logging_permitted:
                    log.exception("Error raised from event of %s", self)
                else:
                    print("Error raised from event")  # No f-string in case str uses logging
                    traceback.print_exc()


class ObjectContainer(EventSentinel):
    """
    A proxy for a given object with EventSentinel functionality added on
    Note: While interprocess event notifications are possible via the async_ flag,
    the contents of the shared object are *not* synchronized between processes;
    only the kwargs passed to the am_event of EventSentinel are synchronized
    """

    def __init__(self, obj, name: str | None = None, notes: str = "", logging_permitted: bool = True) -> None:
        super().__init__(logging_permitted=logging_permitted)
        self._am_obj = None
        self.am_obj = obj
        self.am_name = name if name is not None else NameGenerator.random_name()
        self.am_notes = notes

    # cause events to propagate upward through nested objectcontainers
    @property
    def am_obj(self):
        return self._am_obj

    @am_obj.setter
    def am_obj(self, v):
        if v is self:
            raise ValueError("Cannot set am_obj to self")
        if type(self._am_obj) is ObjectContainer:
            self._am_obj.am_unsubscribe(self.__forwarder)
        if type(v) is ObjectContainer:
            v.am_subscribe(self.__forwarder)
        self._am_obj = v

    @property
    def am_none(self) -> bool:
        return self._am_obj is None

    def __forwarder(self, **kwargs) -> None:
        kwargs["forwarded"] = True
        self.am_event(**kwargs)

    def __getattr__(self, item):
        if item.startswith(("am_", "_am_")):
            return object.__getattribute__(self, item)
        return getattr(self._am_obj, item)

    def __setattr__(self, key, value) -> None:
        if key.startswith(("am_", "_am_")):
            return object.__setattr__(self, key, value)
        return setattr(self._am_obj, key, value)

    def __getitem__(self, item):
        return self._am_obj[item]

    def __setitem__(self, key, value) -> None:
        self._am_obj[key] = value

    def __dir__(self):
        return dir(self._am_obj) + list(self.__dict__) + list(EventSentinel.__dict__) + ["am_obj", "am_full"]

    def __iter__(self):
        return iter(self._am_obj)

    def __len__(self) -> int:
        return len(self._am_obj)

    def __eq__(self, other):
        return self is other or self._am_obj == other

    def __ne__(self, other) -> bool:
        return not self == other

    def __repr__(self) -> str:
        return f"(container: {self.am_name}){repr(self._am_obj)}"
