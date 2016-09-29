import pickle
from threading import Thread
from Queue import Queue

from atom.api import Atom, Int, List, Typed, Value, Dict
from enaml.application import schedule

import ana
from angr import CFG, PathGroup, Project, PathHierarchy

from .jobs import Job
from .registry import Registry

class PathGroups(Atom):
    proj = Typed(Project)
    groups = List(PathGroup, [])

    def add_path_group(self, pg=None):
        if pg is None:
            hierarchy = PathHierarchy(weakkey_path_mapping=True)
            pg = self.proj.factory.path_group(immutable=False, hierarchy=hierarchy)
        self.groups = self.groups + [pg]

        return pg

class Instance(Atom):
    proj = Typed(Project)
    workspaces = List()
    path_groups = Typed(PathGroups)
    cfg = Typed(CFG)
    jobs = List(Job)
    vfgs = Dict()
    registry = Typed(Registry, factory=Registry)
    current_workspace = Typed(object)

    _jobs_queue = Value()

    def __init__(self, **kwargs):
        super(Instance, self).__init__(**kwargs)

        if self.jobs is None or self._jobs_queue is None:
            self.jobs = []
            self._jobs_queue = Queue()

        if self.path_groups is None:
            self.path_groups = PathGroups(proj=self.proj)

        self._start_worker()

    def add_workspace(self, wk):
        self.workspaces = self.workspaces + [wk]

    def add_job(self, job):
        self.jobs = self.jobs + [job]
        self._jobs_queue.put(job)

    def _start_worker(self):
        t = Thread(target=self._worker, name='angr Management Worker Thread')
        t.daemon = True
        t.start()

    def _worker(self):
        while True:
            job = self._jobs_queue.get()
            result = job.run(self)
            schedule(job.finish, args=(self, result))

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

    def get_workspaces(self, sort=None):
        return [ wk for wk in self.workspaces if sort is None or wk.sort == sort ]

from .workspace import WorkspaceData
