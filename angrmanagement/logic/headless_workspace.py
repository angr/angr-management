"""
A workspace without a user interface.

:class:`HeadlessWorkspace` provides what the MCP server, the daemon and the jobs read from a workspace: the instance,
a job manager, plugins and the MCP call history. It has no views, so ``view_manager`` finds none and refreshing is a
no-op. The project database functions here are shared with the Qt workspace.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import logging
from collections import defaultdict
from functools import partial
from typing import TYPE_CHECKING, Any

from angr.angrdb import AngrDB

from angrmanagement.data.instance import Instance
from angrmanagement.data.jobs import DecompileFunctionJob, VariableRecoveryJob
from angrmanagement.data.jobs.loading import LoadAngrDBJob
from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.plugins import PluginManager

from . import GlobalInfo
from .analysis_manager import AnalysisManager
from .jobmanager import JobManager

if TYPE_CHECKING:
    from collections.abc import Callable

    from angr.knowledge_plugins.functions import Function

    from angrmanagement.data.jobs.job import Job

_l = logging.getLogger(__name__)

PSEUDOCODE_FLAVOR = "pseudocode"


#
# Project and database operations shared by every workspace
#


def close_project(instance: Instance) -> None:
    """
    Unload the currently loaded project, returning the instance to an empty state. Does nothing if no project is
    loaded.
    """
    if instance.project.am_none:
        return
    instance.binary_path = None
    instance.original_binary_path = None
    instance.database_path = None
    instance.analysis_configuration = None
    instance._reset_containers()  # pylint:disable=protected-access


def save_database(workspace, file_path: str) -> bool:
    """
    Dump the workspace's project and its knowledge base to an angr database (.adb) file.

    :returns: True on success, False if no project is loaded.
    """
    instance = workspace.main_instance
    if instance.project.am_none:
        return False

    workspace.plugins.handle_project_save(file_path)
    # no connection pool: a pooled SQLite connection keeps the file open, and locked on Windows
    angrdb = AngrDB(project=instance.project.am_obj, nullpool=True)
    extra_info = workspace.plugins.angrdb_store_entries()
    angrdb.dump(file_path, kbs=[instance.kb], extra_info=extra_info)
    instance.database_path = file_path
    return True


def load_database(workspace, file_path: str, on_finish: Callable[..., None]) -> LoadAngrDBJob:
    """Start a background job that loads an angr database; ``on_finish(job)`` runs on the UI thread after it."""
    job = LoadAngrDBJob(workspace.main_instance, file_path, ["global"], other_kbs={}, extra_info={})
    job._on_finish = partial(on_finish, job)  # pylint:disable=protected-access
    workspace.job_manager.add_job(job)
    return job


def apply_loaded_database(workspace, job: LoadAngrDBJob) -> bool:
    """
    Install the project a finished LoadAngrDBJob produced into the workspace and announce it.

    :returns: False if the job produced no project.
    """
    proj = job.project
    if proj is None:
        return False

    instance = workspace.main_instance
    cfg = proj.kb.cfgs["CFGFast"]
    cfb = proj.analyses.CFB()  # it will load functions from kb

    instance.database_path = job.file_path
    instance._reset_containers()  # pylint:disable=protected-access
    instance.project = proj
    instance.cfg = cfg
    instance.cfb = cfb
    instance.project.am_event(initialized=True)

    # trigger callbacks
    workspace.reload()
    for container in (instance.cfb, instance.cfg):
        if isinstance(container, ObjectContainer):
            container.am_event()
    workspace.on_cfg_generated()
    instance.annotations.deserialize(job.extra_info)
    workspace.plugins.angrdb_load_entries(job.extra_info)
    return True


def submit_background_decompilation(instance: Instance, job_manager: JobManager, func: Function) -> None:
    """Queue a decompilation of ``func`` without touching any views, recovering its variables first if needed."""

    def submit_decomp(*_args, **_kwargs) -> None:
        job = DecompileFunctionJob(instance, func, cfg=instance.cfg, flavor=PSEUDOCODE_FLAVOR)
        job_manager.add_job(job)

    if func.ran_cca is False and (func.prototype is None or func.is_prototype_guessed is True):
        # run calling convention analysis for this function first, like the pseudocode view does
        options = instance.analysis_configuration["varec"].to_dict() if instance.analysis_configuration else {}
        options["workers"] = 0
        varrec_job = VariableRecoveryJob(instance, **options, on_finish=submit_decomp, func_addr=func.addr)
        job_manager.add_job(varrec_job)
    else:
        submit_decomp()


#
# The headless workspace
#


class HeadlessViewManager:
    """The view manager of a workspace without views: every lookup finds nothing."""

    def __init__(self) -> None:
        self.views: list[Any] = []
        self.current_tab = None

    @property
    def views_by_category(self) -> defaultdict[str, list[Any]]:
        return defaultdict(list)

    def first_view_in_category(self, category: str):  # pylint:disable=unused-argument
        return None

    def current_view_in_category(self, category: str):  # pylint:disable=unused-argument
        return None

    def raise_view(self, view) -> None:
        pass


class HeadlessWorkspace:
    """
    A workspace for a process without a user interface.

    Create it on the thread that will act as the UI thread, and pump ``GlobalInfo.executor`` there (for example with
    ``job_manager.join_all_jobs()``), because job results and MCP edits are delivered on that thread.

    :param instance:        The instance to work on; a new one by default.
    :param auto_analyze:    Run the default initial analyses when a project without a CFG is set, as the Qt workspace
                            does after its analysis options dialog.
    """

    def __init__(self, instance: Instance | None = None, auto_analyze: bool = True) -> None:
        # the creating thread is the UI thread of the default executor
        _ = GlobalInfo.executor
        self.main_window = None
        self._main_instance = instance if instance is not None else Instance()
        self.job_manager = JobManager(self)
        self.job_manager.job_exception.connect(self._on_job_exception)
        self.view_manager = HeadlessViewManager()
        self.plugins = PluginManager(self)
        self.analysis_manager = AnalysisManager(self)
        self.auto_analyze = auto_analyze
        # read by the MCP load_binary tool; there is no analysis options dialog to suppress here
        self._suppress_analysis_options_dialog = False
        # MCP tool calls made by an AI agent: a list of angrmanagement.mcp.history.MCPCallRecord
        self.mcp_history = ObjectContainer([], name="mcp_history")

        self._main_instance.project.am_subscribe(self._on_project_changed)
        self._main_instance.handle_comment_changed_callback = self.plugins.handle_comment_changed

    @property
    def main_instance(self) -> Instance:
        return self._main_instance

    #
    # What the Qt workspace refreshes; there is nothing to refresh here
    #

    def reload(self, categories: list[str] | None = None) -> None:
        pass

    def refresh(self, categories: list[str] | None = None) -> None:
        pass

    def on_function_updated(self) -> None:
        pass

    def on_cfg_generated(self) -> None:
        pass

    def on_cfg_recovery_started(self, cfb) -> None:
        self.main_instance.cfb = cfb
        self.main_instance.cfb.am_event()

    def jump_to(self, addr: int, view=None, use_animation: bool = False) -> None:  # pylint:disable=unused-argument
        _l.debug("Headless workspace: not jumping to %#x", addr)

    def log(self, msg) -> None:
        if isinstance(msg, BaseException):
            _l.error("%s", msg, exc_info=msg)
        else:
            _l.info("%s", msg)

    #
    # Analyses
    #

    def run_analysis(self) -> None:
        """Run the initial analyses with the default configuration."""
        if self.main_instance.project.am_none:
            return
        if self.main_instance.analysis_configuration is None:
            self.main_instance.analysis_configuration = self.analysis_manager.get_default_analyses_configuration()
        self.analysis_manager.run_analysis()

    def decompile_function(self, func: Function, curr_ins=None, view=None) -> None:  # pylint:disable=unused-argument
        """Decompile ``func`` in the background; there is no pseudocode view to show it in."""
        submit_background_decompilation(self.main_instance, self.job_manager, func)

    #
    # Projects and databases
    #

    def close_project(self) -> None:
        close_project(self.main_instance)

    def save_database(self, file_path: str) -> bool:
        return save_database(self, file_path)

    def load_database(self, file_path: str, on_loaded: Callable[[str], None] | None = None) -> LoadAngrDBJob:
        """Load an angr database in a background job; ``on_loaded(file_path)`` runs once it is installed."""

        def on_finish(job: LoadAngrDBJob, *_args, **_kwargs) -> None:
            if apply_loaded_database(self, job) and on_loaded is not None:
                on_loaded(job.file_path)

        return load_database(self, file_path, on_finish)

    #
    # Callbacks
    #

    def _on_project_changed(self, **kwargs) -> None:  # pylint:disable=unused-argument
        if self.main_instance.project.am_none:
            return
        if self.auto_analyze and not self.main_instance.kb.cfgs.cfgs:
            self._suppress_analysis_options_dialog = False
            GlobalInfo.executor.schedule_async(self.run_analysis)
        self.plugins.handle_project_initialization()

    def _on_job_exception(self, job: Job, ex: BaseException) -> None:
        _l.error('Exception while running job "%s":', job.name, exc_info=ex)
