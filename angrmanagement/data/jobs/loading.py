from typing import List, Optional, Dict, TYPE_CHECKING
import logging

from PySide2.QtWidgets import QMessageBox

import cle
import angr
from angr.angrdb import AngrDB
import archinfo
try:
    import archr
except ImportError:
    archr = None

from .job import Job
from ...logic.threads import gui_thread_schedule
from ...ui.dialogs import LoadBinary

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase

_l = logging.getLogger(__name__)


class LoadTargetJob(Job):
    """
    Job to load archr target and angr project.
    """

    def __init__(self, target, on_finish=None):
        super().__init__("Loading target", on_finish=on_finish)
        self.target = target

    def _run(self, inst):
        self._progress_callback(5)
        with self.target.build().start() as t:
            self._progress_callback(10)
            dsb = archr.arsenal.DataScoutBow(t)
            apb = archr.arsenal.angrProjectBow(t, dsb)
            partial_ld = apb.fire(return_loader=True, perform_relocations=False, load_debug_info=False)
            self._progress_callback(50)
            load_options = gui_thread_schedule(LoadBinary.run, (partial_ld,))
            if load_options is None:
                return

            # Create the project, load it, then record the image name on success
            proj = apb.fire(use_sim_procedures=True, load_options=load_options)
            self._progress_callback(95)
            inst._reset_containers()
            inst.project = proj
            inst.project.am_event()


class LoadBinaryJob(Job):
    """
    Job to display binary load dialog and create angr project.
    """

    def __init__(self, fname, load_options=None, on_finish=None):
        super().__init__("Loading file", on_finish=on_finish)
        self.load_options = load_options or {}
        self.fname = fname

    def _run(self, inst):
        self._progress_callback(5)

        partial_ld = None
        try:
            # Try automatic loading
            partial_ld = cle.Loader(self.fname, perform_relocations=False, load_debug_info=False)
        except archinfo.arch.ArchNotFound as e:
            partial_ld = cle.Loader(self.fname, perform_relocations=False, load_debug_info=False, arch='x86')
            gui_thread_schedule(LoadBinary.binary_arch_detect_failed, (self.fname, str(e)))
        except cle.CLECompatibilityError:
            # Continue loading as blob
            pass

        if partial_ld is None:
            try:
                # Try loading as blob; dummy architecture (x86) required, user will select proper arch
                partial_ld = cle.Loader(self.fname, main_opts={'backend': 'blob', 'arch': 'x86'})
            except cle.CLECompatibilityError:
                # Failed to load executable, even as blob!
                gui_thread_schedule(LoadBinary.binary_loading_failed, (self.fname,))
                return

        self._progress_callback(50)
        new_load_options = gui_thread_schedule(LoadBinary.run, (partial_ld, ))
        if new_load_options is None:
            return

        engine = None
        if hasattr(new_load_options['arch'], 'pcode_arch'):
            engine = angr.engines.UberEnginePcode

        self.load_options.update(new_load_options)

        proj = angr.Project(self.fname, load_options=self.load_options, engine=engine)
        self._progress_callback(95)
        def callback():
            inst._reset_containers()
            inst.project.am_obj = proj
            inst.project.am_event()
        gui_thread_schedule(callback, ())


class LoadAngrDBJob(Job):
    """
    Load an angr database file and return a new angr project.
    """
    def __init__(self, file_path: str, kb_names: List[str], other_kbs: Optional[Dict[str,'KnowledgeBase']]=None,
                 extra_info: Optional[Dict]=None, on_finish=None):
        super().__init__("Loading angr database", on_finish=on_finish)
        self.file_path = file_path
        self.kb_names = kb_names
        self.other_kbs = other_kbs
        self.extra_info = extra_info
        self.blocking = True

        self.project = None

    def _run(self, inst):
        self._progress_callback(5)

        angrdb = AngrDB()
        try:
            proj = angrdb.load(self.file_path,
                               kb_names=self.kb_names,
                               other_kbs=self.other_kbs,
                               extra_info=self.extra_info)
        except angr.errors.AngrIncompatibleDBError as ex:
            _l.critical("Failed to load the angr database because of compatibility issues.", exc_info=True)
            gui_thread_schedule(QMessageBox.critical,
                                (None, 'Error',
                                 "Failed to load the angr database because of compatibility issues.\n"
                                 f"Details: {ex}")
                                )
            return
        except angr.errors.AngrDBError as ex:
            _l.critical("Failed to load the angr database because of compatibility issues.", exc_info=True)
            gui_thread_schedule(QMessageBox.critical,
                                (None, 'Error',
                                 'Failed to load the angr database.\n'
                                 f'Details: {ex}')
                                )
            _l.critical("Failed to load the angr database.", exc_info=True)
            return

        self.project = proj

        self._progress_callback(100)
