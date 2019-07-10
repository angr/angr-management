import pickle
import time
from threading import Thread
from queue import Queue

import ana

from .jobs import CFGGenerationJob
from .object_container import ObjectContainer
from .sync_ctrl import SyncControl
from ..logic import GlobalInfo
from ..logic.threads import gui_thread_schedule_async


class Instance:
    def __init__(self, project=None):
        self.workspace = None

        self.jobs = []
        self._jobs_queue = Queue()
        self.simgrs = ObjectContainer([], name='Global simulation managers list')
        self.states = ObjectContainer([], name='Global states list')
        self.patches = ObjectContainer(None, name='Global patches update notifier')
        self._project_container = ObjectContainer(project, "the current angr project")
        self.cfg_container = ObjectContainer(project, "the current CFG")
        self.interactions = ObjectContainer([], name='Saved program interactions')
        self.sync = SyncControl(self)

        self._start_worker()

        self._cfg = None
        self._cfb = None

        self.database_path = None

        # The image name when loading image
        self.img_name = None

    #
    # Properties
    #

    @property
    def project(self):
        return self._project_container.am_obj

    @project.setter
    def project(self, v):
        self._project_container.am_obj = v
        self._project_container.am_event()

    @property
    def project_container(self):
        return self._project_container

    @property
    def cfg(self):
        return self.cfg_container.am_obj

    @cfg.setter
    def cfg(self, v):
        self.cfg_container.am_obj = v
        self.cfg_container.am_event()

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

    def async_set_cfg(self, cfg):
        self.cfg_container.am_obj = cfg
        # This should not trigger a signal because the CFG is not yet done. We'll trigger a
        # signal on cfg.setter only
        # self.cfg_container.am_event()

    def async_set_cfb(self, cfb):
        self._cfb = cfb

    def set_project(self, project):
        self.project = project

    def set_image(self, image):
        self.img_name = image

    def initialize(self, cfg_args=None):
        if cfg_args is None:
            cfg_args = {}
        cfg_job = CFGGenerationJob(
                on_finish=self.workspace.on_cfg_generated,
                **cfg_args
             )
        self.add_job(cfg_job)

        self._start_daemon_thread(self._refresh_cfg, 'Progressive Refreshing CFG', args=(cfg_job,))

    def add_job(self, job):
        self.jobs.append(job)
        self._jobs_queue.put(job)

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

    #
    # Private methods
    #

    def _start_daemon_thread(self, target, name, args=None):
        t = Thread(target=target, name=name, args=args if args else tuple())
        t.daemon = True
        t.start()

    def _start_worker(self):
        self._start_daemon_thread(self._worker, 'angr Management Worker Thread')

    def _worker(self):
        while True:
            if self._jobs_queue.empty():
                gui_thread_schedule_async(self._set_status, args=("Ready.",))

            job = self._jobs_queue.get()
            gui_thread_schedule_async(self._set_status, args=("Working...",))

            result = job.run(self)
            gui_thread_schedule_async(job.finish, args=(self, result))

            self.jobs.remove(job)

    def _set_status(self, status_text):
        GlobalInfo.main_window.status = status_text

    def _refresh_cfg(self, cfg_job):
        time.sleep(1.0)
        while True:
            if self._cfg is not None:
                if self.workspace is not None:
                    gui_thread_schedule_async(lambda: self.workspace.reload())

            time.sleep(0.3)
            if cfg_job not in self.jobs:
                break
