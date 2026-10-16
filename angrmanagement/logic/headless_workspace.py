"""
A workspace without a user interface.

:class:`HeadlessWorkspace` provides what the MCP server, the daemon and the jobs read from a workspace: the instance,
a job manager, plugins and the MCP call history. It has no views, so ``view_manager`` finds none and refreshing is a
no-op.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angrmanagement.data.jobs import DecompileFunctionJob, VariableRecoveryJob

from . import GlobalInfo
from .view_manager import BaseViewManager
from .workspace import BaseWorkspace

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function

    from angrmanagement.data.instance import Instance
    from angrmanagement.data.jobs.job import Job

    from .jobmanager import JobManager

_l = logging.getLogger(__name__)

PSEUDOCODE_FLAVOR = "pseudocode"


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


class HeadlessViewManager(BaseViewManager):
    """The view manager of a workspace without views: it creates none, so every lookup finds nothing."""

    def create_view(self, category: str, position: str | None = None) -> None:  # pylint:disable=unused-argument
        return None


class HeadlessWorkspace(BaseWorkspace):
    """
    A workspace for a process without a user interface.

    Create it on the thread that will act as the UI thread, and pump ``GlobalInfo.executor`` there (for example with
    ``job_manager.join_all_jobs()``), because job results and MCP edits are delivered on that thread.

    It is a :class:`~angrmanagement.logic.workspace.BaseWorkspace` whose view manager creates no views, so everything
    that would show something does nothing; jumping is not even sent to the UI thread, and decompilation runs in the
    background.

    :param instance:        The instance to work on; a new one by default.
    :param auto_analyze:    Run the default initial analyses when a project without a CFG is set, as the Qt workspace
                            does after its analysis options dialog.
    """

    VIEW_MANAGER_CLASS = HeadlessViewManager

    def __init__(self, instance: Instance | None = None, auto_analyze: bool = True) -> None:
        # the creating thread is the UI thread of the default executor
        _ = GlobalInfo.executor
        self.auto_analyze = auto_analyze
        super().__init__(None, instance)

    def jump_to(self, addr: int, view=None, use_animation: bool = False) -> None:  # pylint:disable=unused-argument
        _l.debug("Headless workspace: not jumping to %#x", addr)

    def log(self, msg) -> None:
        if isinstance(msg, BaseException):
            _l.error("%s", msg, exc_info=msg)
        else:
            _l.info("%s", msg)

    def decompile_function(self, func: Function, curr_ins=None, view=None) -> None:  # pylint:disable=unused-argument
        """Decompile ``func`` in the background; there is no pseudocode view to show it in."""
        submit_background_decompilation(self.main_instance, self.job_manager, func)

    #
    # Callbacks
    #

    def _instance_project_initalization(self, **kwargs) -> None:
        if self.auto_analyze:
            super()._instance_project_initalization(**kwargs)
        elif not self.main_instance.project.am_none:
            self.plugins.handle_project_initialization()

    def _handle_job_exception(self, job: Job, ex: BaseException) -> None:
        _l.error('Exception while running job "%s":', job.name, exc_info=ex)
