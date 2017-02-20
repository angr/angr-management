import pickle
from threading import Thread
from Queue import Queue

import ana
from angr import CFG, PathGroup, Project, PathHierarchy

from .jobs import PGStepJob
from .jobs import CFGGenerationJob
from ..logic.threads import gui_thread_schedule
from .states import StateManager


class PathGroups(object):
    def __init__(self, instance, project):
        self.instance = instance
        self.project = project

        self.groups = [ ]
        self._widget = None

    def add_pathgroup(self, pg=None):
        if pg is None:
            hierarchy = PathHierarchy(weakkey_path_mapping=True)
            pg = self.project.factory.path_group(immutable=False, hierarchy=hierarchy)
        self.groups.append(pg)

        self.widget.add_pathgroup(pg)

        return pg

    def step_pathgroup(self, pg):
        if self.instance is None:
            pg.step(until_branch=True)
        else:
            self.instance.add_job(PGStepJob(pg, callback=self._pathgroup_stepped, until_branch=True))

    def link_widget(self, path_groups_widget):
        self.widget = path_groups_widget

        self.widget.reload()

    #
    # Callbacks
    #

    def _pathgroup_stepped(self, result):
        if self.widget is not None:
            self.widget.refresh()


class Instance(object):
    def __init__(self, project):
        self.project = project

        self.workspace = None

        self.jobs = []
        self._jobs_queue = Queue()
        self.path_groups = PathGroups(instance=self, project=self.project)
        self.states = StateManager(instance=self, project=self.project)

        self._start_worker()

        self._cfg = None

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

    #
    # Public methods
    #

    def initialize(self, cfg_args=None):
        if cfg_args is None:
            cfg_args = { }
        self.add_job(CFGGenerationJob(**cfg_args))

    def add_job(self, job):
        self.jobs.append(job)
        self._jobs_queue.put(job)

    def _start_worker(self):
        t = Thread(target=self._worker, name='angr Management Worker Thread')
        t.daemon = True
        t.start()

    def _worker(self):
        while True:
            job = self._jobs_queue.get()
            result = job.run(self)
            gui_thread_schedule(job.finish, args=(self, result))

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
