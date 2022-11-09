import os
import queue
import logging
import weakref
import threading
from typing import Optional
from multiprocessing import Queue

from ..utils.namegen import NameGenerator


l = logging.getLogger(__name__)

class EventSentinel:
    """
    A class which exposes methods for listeners to subscribe
    methods for callbacks when an event is triggered
    Callbacks may be synchronous or asynchronous
    Only asynchronous callbacks may be triggered by an event in a different process
    """
    def __init__(self, async_: bool = False):
        """
        If async_, __init__ constructs an async thread
        :param async_: If true, callbacks triggered via am_event will asynchronous
        """
        self.am_subscribers = []
        self.am_async: bool = async_
        # Variables only used in asynchronous mode
        self._am_queue: Optional[Queue] = Queue() if async_ else None
        self._am_pid: Optional[int] = os.getpid() if async_ else None
        if self.am_async:
            threading.Thread(
                target=self._async_loop,
                args=(weakref.proxy(self),),
                daemon=True,
            ).start()

    def am_subscribe(self, listener) -> None:
        """
        Subscribe listener to the event
        If async, may only be called from the process the async loop is in
        :param listener: The listener to subscribe to the event
        :return: None
        """
        if self.am_async and os.getpid() != self._am_pid:
            raise RuntimeError("Subscribe only works from the process the async thread lives in")
        if listener is not None:
            self.am_subscribers.append(listener)

    def am_unsubscribe(self, listener):
        """
        Unsubscribe listener to the event
        If async, may only be called from the process the async loop is in
        :param listener: The listener to subscribe to the event
        :return: None
        """
        if self.am_async and os.getpid() != self._am_pid:
            raise RuntimeError("Unsubscribe only works from the process the async thread lives in")
        if listener is not None:
            try:
                self.am_subscribers.remove(listener)
            except ValueError:
                l.warning("Double-unsubscribe of %s from %s", listener, self)

    def am_event(self, **kwargs):
        if self.am_async:
            self._am_queue.put(kwargs)  # Should not block, queue has no size limit
        else:
            self._am_event(kwargs)

    def _am_event(self, kwargs):
        for listener in self.am_subscribers:
            try:
                listener(**kwargs)
            except Exception:  # pylint: disable=broad-except
                l.exception("Error raised from event of %s", self)

    @staticmethod
    def _async_loop(self: weakref.ProxyType) -> None:
        """
        Call am_event on every item put into the queue while self exists
        :param self: A weak reference to the EventSentinel
        :return: None
        """
        if self.am_async is False:
            raise RuntimeError("Must be called on an async EventSentinel")
        try:
            while True:
                try:  # We loop with a timeout to recheck if self is still alive
                    self._am_event(self._am_queue.get(block=True, timeout=.05))
                except queue.Empty:
                    pass
        except ReferenceError:
            l.debug("Event loop for async EventSentinel died")

class ObjectContainer(EventSentinel):
    def __init__(self, obj, name=None, notes='', async_: bool = False):
        super().__init__(async_)
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
        if type(self._am_obj) is ObjectContainer:
            self._am_obj.am_unsubscribe(self.__forwarder)
        if type(v) is ObjectContainer:
            v.am_subscribe(self.__forwarder)
        self._am_obj = v

    @property
    def am_none(self):
        return self._am_obj is None

    def __forwarder(self, **kwargs):
        kwargs['forwarded'] = True
        self.am_event(**kwargs)

    def __getattr__(self, item):
        if item.startswith('am_') or item.startswith('_am_'):
            return object.__getattribute__(self, item)
        return getattr(self._am_obj, item)

    def __setattr__(self, key, value):
        if key.startswith('am_') or key.startswith('_am_'):
            return object.__setattr__(self, key, value)
        return setattr(self._am_obj, key, value)

    def __getitem__(self, item):
        return self._am_obj[item]

    def __setitem__(self, key, value):
        self._am_obj[key] = value

    def __dir__(self):
        return dir(self._am_obj) + list(self.__dict__) + list(EventSentinel.__dict__) + ['am_obj', 'am_full']

    def __iter__(self):
        return iter(self._am_obj)

    def __len__(self):
        return len(self._am_obj)

    def __eq__(self, other):
        return self is other or self._am_obj == other

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return '(container: %s)%s' % (self.am_name, repr(self._am_obj))