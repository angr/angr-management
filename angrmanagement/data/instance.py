import pickle
from threading import Thread
from Queue import Queue

import ana

from .states import StateRecord
from .jobs import CFGGenerationJob
from ..logic import GlobalInfo
from ..logic.threads import gui_thread_schedule_async
from ..utils.namegen import NameGenerator


class EventSentinel(object):
    def __init__(self):
        self.am_subscribers = []

    def am_subscribe(self, listener):
        self.am_subscribers.append(listener)

    def am_unsubscribe(self, listener):
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

    # cause events to propogate upward through nested objectcontainers
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
        return '(container %s)%s' % (self.am_name, repr(self._am_obj))


class Instance(object):
    def __init__(self, project=None):
        self.project = project

        self.workspace = None

        self.jobs = []
        self._jobs_queue = Queue()
        self.simgrs = ObjectContainer([], name='Global simulation managers list')
        self.states = ObjectContainer([], name='Global states list')

        self._start_worker()

        self._cfg = None
        self._cfb = None

    #
    # Properties
    #

    @property
    def cfg(self):
        return self._cfg

    @cfg.setter
    def cfg(self, v):
        self._cfg = v

        # notify the workspace
        if self.workspace is not None:
            self.workspace.reload()

    @property
    def cfb(self):
        return self._cfb

    @cfb.setter
    def cfb(self, v):
        self._cfb = v

    #
    # Public methods
    #

    def set_project(self, project):
        self.project = project
        self.states.am_obj = StateRecord.basics()
        self.states.am_event(src='set_project')

    def initialize(self, cfg_args=None):
        if cfg_args is None:
            cfg_args = {}
        self.add_job(
            CFGGenerationJob(
                on_finish=self.workspace.on_cfg_generated,
                **cfg_args
             )
        )

    def add_job(self, job):
        self.jobs.append(job)
        self._jobs_queue.put(job)

    def _start_worker(self):
        t = Thread(target=self._worker, name='angr Management Worker Thread')
        t.daemon = True
        t.start()

    def _worker(self):
        while True:
            if self._jobs_queue.empty():
                gui_thread_schedule_async(self._set_status, args=("Ready.",))

            job = self._jobs_queue.get()
            gui_thread_schedule_async(self._set_status, args=("Working...",))

            result = job.run(self)
            gui_thread_schedule_async(job.finish, args=(self, result))

    def _set_status(self, status_text):
        GlobalInfo.main_window.status = status_text

    def save(self, loc):
        with open(loc, 'wb') as f:
            pickled = pickle.dumps(self)
            store = ana.get_dl()._state_store
            pickle.dump({'store': store, 'pickled': pickled}, f)

    @staticmethod
    def from_file(loc):
        with open(loc, 'rb') as f:
            saved = pickle.load(f)
            ana.get_dl()._state_store = saved['store']
            return pickle.loads(saved['pickled'])
