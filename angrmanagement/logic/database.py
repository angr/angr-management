"""
Opening, saving and closing a project's angr database, for every workspace.

These are the parts of :class:`~angrmanagement.logic.workspace.BaseWorkspace`'s project methods that need no user
interface.
"""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from angr.angrdb import AngrDB

from angrmanagement.data.jobs.loading import LoadAngrDBJob
from angrmanagement.data.object_container import ObjectContainer

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.data.instance import Instance


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
    instance.project.am_obj = proj
    instance.cfg.am_obj = cfg
    instance.cfb.am_obj = cfb
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
