import threading

from PySide2.QtCore import QEvent, QCoreApplication

from . import GlobalInfo


class ExecuteCodeEvent(QEvent):
    def __init__(self, callable, args=None, kwargs=None):
        super().__init__(QEvent.User)
        self.callable = callable
        self.args = args
        self.kwargs = kwargs
        self.event = threading.Event()
        self.result = None
        self.exception = None

    def execute(self):
        if self.kwargs is None:
            if self.args is None:
                return self.callable()
            else:
                return self.callable(*self.args)
        else:
            if self.args is None:
                return self.callable(**self.kwargs)
            else:
                return self.callable(*self.args, **self.kwargs)


class GUIObjProxy:
    """
    Derived from http://code.activestate.com/recipes/496741-object-proxying/
    """
    __slots__ = ["_obj", "__weakref__"]

    def __init__(self, obj):
        object.__setattr__(self, "_obj", obj)

    #
    # proxying (special cases)
    #
    def __getattribute__(self, name):
        result = gui_thread_schedule(lambda: getattr(object.__getattribute__(self, "_obj"), name))
        if result is None:
            return result
        if type(result) in [int, float, str, bool]:
            return result
        return GUIObjProxy(result)

    def __delattr__(self, name):
        gui_thread_schedule(lambda: delattr(object.__getattribute__(self, "_obj"), name))

    def __setattr__(self, name, value):
        gui_thread_schedule(lambda: setattr(object.__getattribute__(self, "_obj"), name, value))

    def __nonzero__(self):
        return gui_thread_schedule(lambda: bool(object.__getattribute__(self, "_obj")))

    def __str__(self):
        return gui_thread_schedule(lambda: str(object.__getattribute__(self, "_obj")))

    def __repr__(self):
        return gui_thread_schedule(lambda: repr(object.__getattribute__(self, "_obj")))

    #
    # factories
    #
    _special_names = [
        '__abs__', '__add__', '__and__', '__call__', '__cmp__', '__coerce__',
        '__contains__', '__delitem__', '__delslice__', '__div__', '__divmod__',
        '__eq__', '__float__', '__floordiv__', '__ge__', '__getitem__',
        '__getslice__', '__gt__', '__hash__', '__hex__', '__iadd__', '__iand__',
        '__idiv__', '__idivmod__', '__ifloordiv__', '__ilshift__', '__imod__',
        '__imul__', '__int__', '__invert__', '__ior__', '__ipow__', '__irshift__',
        '__isub__', '__iter__', '__itruediv__', '__ixor__', '__le__', '__len__',
        '__long__', '__lshift__', '__lt__', '__mod__', '__mul__', '__ne__',
        '__neg__', '__oct__', '__or__', '__pos__', '__pow__', '__radd__',
        '__rand__', '__rdiv__', '__rdivmod__', '__reduce__', '__reduce_ex__',
        '__repr__', '__reversed__', '__rfloorfiv__', '__rlshift__', '__rmod__',
        '__rmul__', '__ror__', '__rpow__', '__rrshift__', '__rshift__', '__rsub__',
        '__rtruediv__', '__rxor__', '__setitem__', '__setslice__', '__sub__',
        '__truediv__', '__xor__', 'next',
    ]

    @classmethod
    def _create_class_proxy(cls, theclass):
        """
        Creates a proxy for the given class.
        """

        def make_method(name):
            def method(self, *args, **kw):
                return gui_thread_schedule(lambda: getattr(object.__getattribute__(self, "_obj"), name)(*args, **kw))

            return method

        namespace = {}
        for name in cls._special_names:
            if hasattr(theclass, name):
                namespace[name] = make_method(name)
        return type("%s(%s)" % (cls.__name__, theclass.__name__), (cls,), namespace)

    def __new__(cls, obj, *args, **kwargs):
        """
        creates an proxy instance referencing `obj`. (obj, *args, **kwargs) are
        passed to this class' __init__, so deriving classes can define an
        __init__ method of their own.
        note: _class_proxy_cache is unique per deriving class (each deriving
        class must hold its own cache)
        """
        try:
            cache = cls.__dict__["_class_proxy_cache"]
        except KeyError:
            cls._class_proxy_cache = cache = {}
        try:
            theclass = cache[obj.__class__]
        except KeyError:
            cache[obj.__class__] = theclass = cls._create_class_proxy(obj.__class__)
        ins = object.__new__(theclass)
        theclass.__init__(ins, obj, *args, **kwargs)
        return ins


def is_gui_thread():
    return threading.get_ident() == GlobalInfo.gui_thread or GlobalInfo.gui_thread is None


def gui_thread_schedule(callable, args=None, timeout=None):
    if is_gui_thread():
        if args is None:
            return callable()
        else:
            return callable(*args)

    event = ExecuteCodeEvent(callable, args)
    try:
        QCoreApplication.postEvent(GlobalInfo.main_window, event)
    except RuntimeError:
        # the application is exiting and the main window has been destroyed. just let it go
        return None

    event.event.wait(timeout=timeout)  # TODO: unsafe. to be fixed later.
    if not event.event.is_set():
        # it timed out without getting scheduled to execute...
        return None

    if event.exception is not None:
        raise event.exception

    return event.result


def gui_thread_schedule_async(callable, args=None, kwargs=None):
    if is_gui_thread():
        if kwargs is None:
            if args is None:
                callable()
            else:
                callable(*args)
        else:
            if args is None:
                callable(**kwargs)
            else:
                callable(*args, **kwargs)
        return

    event = ExecuteCodeEvent(callable, args=args, kwargs=kwargs)
    try:
        QCoreApplication.postEvent(GlobalInfo.main_window, event)
    except RuntimeError:
        # the application is exiting and the main window has been destroyed. just let it go
        pass
