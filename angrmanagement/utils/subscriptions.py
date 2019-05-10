import logging
from weakref import WeakKeyDictionary

_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)

class SetOnlyDescriptor:
    def __init__(self, backer=None):
        self._backer = backer

    def __set__(self, instance, value):
        self._backer[instance] = value

class BasicDescriptor(SetOnlyDescriptor):
    def __init__(self, default_val=None, backer=None):
        backer = WeakKeyDictionary() if backer is None else backer
        super().__init__(backer=backer)
        self._default_val = default_val

    def __get__(self, instance, instancety=None):
        if instance not in self._backer:
            self._backer[instance] = self._default_val()
        return self._backer[instance]

class Subscribable(BasicDescriptor):
    def __init__(self, subscribers_prop, name, default_val=None):
        super().__init__(default_val=default_val)
        self._subscribers_prop = subscribers_prop
        self._name = name

    def __set__(self, instance, value):
        old_val = super().__get__(instance)
        super().__set__(instance, value)
        subscribers = self._subscribers_prop.__get__(instance)
        _l.debug('Detected change in %s', self._name)
        for subscriber in list(subscribers):
            if subscriber(old_val, value):
                subscribers.remove(subscriber)

def create_subscribable(cls, name):
    subscribers_prop_name = '_on_{}_changed'.format(name)
    subscribers_prop = BasicDescriptor(set)
    no_event_name = '{}_no_event'.format(name)
    setattr(cls, subscribers_prop_name, subscribers_prop)
    subscribable = Subscribable(subscribers_prop, name, lambda: None)
    setattr(cls, name, subscribable)
    setattr(cls, no_event_name, SetOnlyDescriptor(subscribable._backer))
    subscribe_method_name = 'subscribe_to_{}'.format(name)
    def subscribe_method(self, f):
        subscribers_prop.__get__(self).add(f)
    setattr(cls, subscribe_method_name, subscribe_method)

def subscribables(*names):
    def _decorator(cls):
        for name in names:
            create_subscribable(cls, name)
        return cls
    return _decorator
