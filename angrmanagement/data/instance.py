import pickle
from threading import Thread
from Queue import Queue

import ana
from angr import StateHierarchy

from .jobs import PGStepJob, PGExploreJob
from .jobs import CFGGenerationJob
from ..logic import GlobalInfo
from ..logic.threads import gui_thread_schedule_async
from .states import StateManager
from ..utils.namegen import NameGenerator


class PathGroupDescriptor(object):
    def __init__(self, name, pg):
        self.name = name
        self.pg = pg

    def __repr__(self):
        return "<PathGroup %s>" % self.name


class PathGroups(object):
    def __init__(self, instance, project):
        self.instance = instance
        self.project = project

        self.groups = [ ]
        self._widget = None

    def add_pathgroup(self, pg_desc=None):
        """
        Add a new path group descriptor.

        :param PathGroupDescriptor pg_desc:
        :return: The added/created path group descriptor.
        """

        if pg_desc is None:
            hierarchy = StateHierarchy()
            pg = self.project.factory.path_group(immutable=False, hierarchy=hierarchy)
            pg_desc = PathGroupDescriptor(NameGenerator.random_name(), pg)

        self.groups.append(pg_desc)

        self._widget.add_pathgroup(pg_desc)

        return pg_desc

    def step_pathgroup(self, pg, until_branch=True, async=True):
        if self.instance is None or not async:
            pg.step(until_branch=until_branch)
        else:
            self.instance.add_job(PGStepJob(pg, callback=self._pathgroup_stepped, until_branch=until_branch))

    def explore_pathgroup(self, pg, async=True, avoid=None, find=None, step_callback=None):

        if self.instance is None or not async:
            # TODO: implement it
            pass

        else:
            self.instance.add_job(PGExploreJob(pg, avoid=avoid, find=find, callback=self._pathgroup_explored,
                                               step_callback=step_callback,
                                               )
                                  )

    def link_widget(self, path_groups_widget):
        self._widget = path_groups_widget

        self._widget.reload()

    def refresh_widget(self):
        if self._widget is None:
            return

        self._widget.refresh()

    #
    # Callbacks
    #

    def _pathgroup_stepped(self, result):
        if self._widget is not None:
            self._widget.refresh()

    def _pathgroup_explored(self, result):
        if self._widget is not None:
            self._widget.refresh()


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
