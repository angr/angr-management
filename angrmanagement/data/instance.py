import pickle
from threading import Thread
from Queue import Queue

import ana
from angr import StateHierarchy

from .jobs import SimGrStepJob, PGExploreJob
from .jobs import CFGGenerationJob
from ..logic import GlobalInfo
from ..logic.threads import gui_thread_schedule_async
from .states import StateManager
from ..utils.namegen import NameGenerator


class SimulationManagerDescriptor(object):
    def __init__(self, name, pg):
        self.name = name
        self.pg = pg

    def __repr__(self):
        return "<SimGr %s>" % self.name


class SimulationManagers(object):
    def __init__(self, instance, project):
        self.instance = instance
        self.project = project

        self.groups = [ ]
        self._widget = None

    def add_simgr(self, pg_desc=None):
        """
        Add a new simulation manager descriptor.

        :param SimulationManagerDescriptor pg_desc:
        :return: The added/created simulation manager descriptor.
        """

        if pg_desc is None:
            hierarchy = StateHierarchy()
            pg = self.project.factory.simgr(immutable=False, hierarchy=hierarchy, save_unconstrained=True,
                                            save_unsat=True)
            pg_desc = SimulationManagerDescriptor(NameGenerator.random_name(), pg)

        self.groups.append(pg_desc)

        self._widget.add_simgr(pg_desc)

        return pg_desc

    def step_simgr(self, simgr, until_branch=True, async=True):
        if self.instance is None or not async:
            simgr.step(until_branch=until_branch)
            print simgr, simgr.stashes
            self._simgr_stepped(None)
        else:
            self.instance.add_job(SimGrStepJob(simgr, callback=self._simgr_stepped, until_branch=until_branch))

    def explore_simgr(self, pg, async=True, avoid=None, find=None, step_callback=None):

        if self.instance is None or not async:
            # TODO: implement it
            pass

        else:
            self.instance.add_job(PGExploreJob(pg, avoid=avoid, find=find, callback=self._simgr_explored,
                                               step_callback=step_callback,
                                               )
                                  )

    def link_widget(self, simgrs_widget):
        self._widget = simgrs_widget

        self._widget.reload()

    def refresh_widget(self):
        if self._widget is None:
            return

        self._widget.refresh()

    #
    # Callbacks
    #

    def _simgr_stepped(self, result):
        if self._widget is not None:
            self._widget.refresh()

    def _simgr_explored(self, result):
        if self._widget is not None:
            self._widget.refresh()


class Instance(object):
    def __init__(self, project):
        self.project = project

        self.workspace = None

        self.jobs = []
        self._jobs_queue = Queue()
        self.simgrs = SimulationManagers(instance=self, project=self.project)
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
