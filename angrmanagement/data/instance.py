import pickle
from threading import Thread
from Queue import Queue

from atom.api import Atom, Int, List, Typed, Value, Dict
from enaml.application import schedule

import ana
from angr import CFG, PathGroup, Project

from .jobs import Job
from .registry import Registry

class PathGroups(Atom):
    proj = Typed(Project)
    groups = List(PathGroup, [])

    def add_path_group(self, pg=None):
        if pg is None:
            pg = self.proj.factory.path_group(immutable=False, strong_path_mapping=True)
        self.groups = self.groups + [pg]

class Instance(Atom):
    proj = Typed(Project)
    workspaces = List()
    path_groups = Typed(PathGroups)
    cfg = Typed(CFG)
    jobs = List(Job)
    vfgs = Dict()
    registry = Typed(Registry, factory=Registry)

    _jobs_queue = Value()

    def __init__(self, **kwargs):
        super(Instance, self).__init__(**kwargs)

        if self.jobs is None or self._jobs_queue is None:
            self.jobs = []
            self._jobs_queue = Queue()

        if self.path_groups is None:
            self.path_groups = PathGroups(proj=self.proj)
            # ehhhhhh let's create one by default because i like to be lazy
            self.path_groups.add_path_group()

        self._start_worker()

    def add_workspace(self, wk):
        self.workspaces = self.workspaces + [wk]

    def add_job(self, job):
        self.jobs = self.jobs + [job]
        self._jobs_queue.put(job)

    def _start_worker(self):
        t = Thread(target=self._worker, name='Angr Management Worker Thread')
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

from .workspace import WorkspaceData
