import time
from threading import Thread
from queue import Queue
from typing import List, Optional, Type, Union, Callable

import angr
from angr.block import Block
from angr.analyses.disassembly import Instruction

from .jobs import CFGGenerationJob
from .object_container import ObjectContainer
from .sync_ctrl import SyncControl
from ..logic import GlobalInfo
from ..logic.threads import gui_thread_schedule_async
from ..daemon.client import DaemonClient


class Instance:
    def __init__(self, project=None):
        # delayed import
        from ..ui.views.interaction_view import PlainTextProtocol, ProtocolInteractor, SavedInteraction

        self.workspace = None

        self.jobs = []
        self._jobs_queue = Queue()

        self._project_container = ObjectContainer(project, "The current angr project")
        self._project_container.am_subscribe(self.initialize)
        self.extra_containers = {}
        self._container_defaults = {}

        self.register_container('simgrs', lambda: [], List[angr.SimulationManager], 'Global simulation managers list')
        self.register_container('states', lambda: [], List[angr.SimState], 'Global states list')
        self.register_container('patches', lambda: None, None, 'Global patches update notifier') # dummy
        self.register_container('cfg_container', lambda: None, Optional[angr.knowledge_plugins.cfg.CFGModel], "The current CFG")
        self.register_container('cfb_container', lambda: None, Optional[angr.analyses.cfg.CFBlanket], "The current CFBlanket")
        self.register_container('interactions', lambda: [], List[SavedInteraction], 'Saved program interactions')
        # TODO: the current setup will erase all loaded protocols on a new project load! do we want that?
        self.register_container('interaction_protocols', lambda: [PlainTextProtocol], List[Type[ProtocolInteractor]], 'Available interaction protocols')

        # Callbacks
        self._insn_backcolor_callback = None  # type: Union[None, Callable[[int, bool], None]]   #  (addr, is_selected)
        self._label_rename_callback = None  # type: Union[None, Callable[[int, str], None]]      #  (addr, new_name)
        self._set_comment_callback = None  # type: Union[None, Callable[[int, str], None]]       #  (addr, comment_text)

        self.sync = SyncControl(self)
        self.cfg_args = None
        self._disassembly = {}

        self._start_worker()

        self.database_path = None

        # The image name when loading image
        self.img_name = None

        self.initialized = False

    #
    # Properties
    #

    @property
    def project(self) -> Optional[angr.Project]:
        return self._project_container.am_obj

    @project.setter
    def project(self, v):
        self._project_container.am_obj = v
        self._project_container.am_event()

    @property
    def project_container(self):
        return self._project_container

    @property
    def kb(self):
        if self.project is None:
            return None
        return self.project.kb

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
        """
        Get the CFBlanket instance.

        :rtype: angr.analyses.cfg.cfb.CFBlanket
        """
        return self.cfb_container.am_obj

    @cfb.setter
    def cfb(self, v):
        self.cfb_container.am_obj = v
        self.cfb_container.am_event()

    def __getattr__(self, k):
        try:
            return self.extra_containers[k]
        except KeyError as e:
            raise AttributeError(k) from e

    def __dir__(self):
        return list(super().__dir__()) + list(self.extra_containers)

    @property
    def insn_backcolor_callback(self):
        return self._insn_backcolor_callback

    @insn_backcolor_callback.setter
    def insn_backcolor_callback(self, v):
        self._insn_backcolor_callback = v

    @property
    def label_rename_callback(self):
        return self._label_rename_callback

    @label_rename_callback.setter
    def label_rename_callback(self, v):
        self._label_rename_callback = v

    @property
    def set_comment_callback(self):
        return self._set_comment_callback

    @set_comment_callback.setter
    def set_comment_callback(self, v):
        self._set_comment_callback = v

    #
    # Public methods
    #

    def register_method(self, name, method):
        if hasattr(self, name):
            existing_method = getattr(self, name)
            if existing_method == method:
                return
            raise ValueError("Method %s has already been registered under name %s." % (
                existing_method, name
            ))

        setattr(self, name, method)

    def register_container(self, name, default_val_func, ty, description):
        if name in self.extra_containers:
            cur_ty = self._container_defaults[name][1]
            if ty != cur_ty:
                raise Exception("Container %s already registered with different type: %s != %s" % (name, ty, cur_ty))

        else:
            self._container_defaults[name] = (default_val_func, ty)
            self.extra_containers[name] = ObjectContainer(default_val_func(), description)

    def async_set_cfg(self, cfg):
        self.cfg_container.am_obj = cfg
        # This should not trigger a signal because the CFG is not yet done. We'll trigger a
        # signal on cfg.setter only
        # self.cfg_container.am_event()

    def async_set_cfb(self, cfb):
        self.cfb_container.am_obj = cfb
        # should not trigger a signal

    def set_project(self, project, cfg_args=None):

        try:
            DaemonClient.register_binary(project.loader.main_object.binary,
                                         project.loader.main_object.md5,
                                         project.loader.main_object.sha256)
        except Exception as ex:
            print(ex)

        self._project_container.am_obj = project
        self._project_container.am_event(cfg_args=cfg_args)

    def set_image(self, image):
        self.img_name = image

    def initialize(self, cfg_args=None):
        for name in self.extra_containers:
            self.extra_containers[name].am_obj = self._container_defaults[name][0]()
            self.extra_containers[name].am_event()

        if not self.initialized:
            self.initialized = True

            if cfg_args is None:
                cfg_args = {}
            # save cfg_args
            self.cfg_args = cfg_args

            # generate CFG
            cfg_job = self.generate_cfg()

            # start daemon
            self._start_daemon_thread(self._refresh_cfg, 'Progressively Refreshing CFG', args=(cfg_job,))

    def generate_cfg(self):
        cfg_job = CFGGenerationJob(
            on_finish=self.workspace.on_cfg_generated,
            **self.cfg_args
        )
        self.add_job(cfg_job)
        return cfg_job

    def add_job(self, job):
        self.jobs.append(job)
        self._jobs_queue.put(job)

    def get_instruction_text_at(self, addr):
        """
        Get the text representation of an instruction at `addr`.

        :param int addr:    Address of the instruction.
        :return:            Text representation of the instruction, or None if no instruction can be found there.
        :rtype:             Optional[str]
        """

        if self.cfb is None:
            return None

        try:
            obj_addr, obj = self.cfb.floor_item(addr)
        except KeyError:
            # no object before addr exists
            return None

        if isinstance(obj, Block):
            for insn in obj.capstone.insns:
                if insn.address == addr:
                    insn_piece = Instruction(insn, None, project=self.project)
                    return insn_piece.render()[0]
        return None

    #
    # Private methods
    #

    def _start_daemon_thread(self, target, name, args=None):
        t = Thread(target=target, name=name, args=args if args else tuple())
        t.daemon = True
        t.start()

    def _start_worker(self):
        self._start_daemon_thread(self._worker, 'angr-management Worker Thread')

    def _worker(self):
        while True:
            if self._jobs_queue.empty():
                gui_thread_schedule_async(self._set_status, args=("Ready.",))

            job = self._jobs_queue.get()
            gui_thread_schedule_async(self._set_status, args=("Working...",))

            try:
                result = job.run(self)
            except Exception as e:
                self.workspace.log('Exception while running job "%s":' % job.name)
                self.workspace.log(e)
            else:
                gui_thread_schedule_async(job.finish, args=(self, result))

    def _set_status(self, status_text):
        GlobalInfo.main_window.status = status_text

    def _refresh_cfg(self, cfg_job):
        time.sleep(1.0)
        while True:
            if self.cfg is not None:
                if self.workspace is not None:
                    gui_thread_schedule_async(self.workspace.reload, kwargs={
                                                                             'categories': ['disassembly', 'functions'],
                                                                             }
                                              )

            time.sleep(0.3)
            if cfg_job not in self.jobs:
                break
