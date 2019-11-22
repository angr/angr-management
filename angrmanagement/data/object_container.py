
from ..utils.namegen import NameGenerator


class EventSentinel:
    def __init__(self):
        self.am_subscribers = []

    def am_subscribe(self, listener):
        if listener is not None:
            self.am_subscribers.append(listener)

    def am_unsubscribe(self, listener):
        if listener is not None:
            self.am_subscribers.remove(listener)

    def am_event(self, **kwargs):
        for listener in self.am_subscribers:
            listener(**kwargs)


class ObjectContainer(EventSentinel):
    def __init__(self, obj, name=None, notes=''):
        super(ObjectContainer, self).__init__()
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
        setattr(self._am_obj, key, value)

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
        return not (self == other)

    def __repr__(self):
        return '(container: %s)%s' % (self.am_name, repr(self._am_obj))

