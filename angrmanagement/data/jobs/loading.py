
import cle
import angr
try:
    import archr
except ImportError:
    archr = None

from .job import Job
from ...logic.threads import gui_thread_schedule
from ...ui.dialogs import LoadBinary


class LoadTargetJob(Job):
    def __init__(self, target, on_finish=None):
        super().__init__("Loading target", on_finish=on_finish)
        self.target = target

    def run(self, inst):
        self._progress_callback(5)
        with self.target.build().start() as t:
            self._progress_callback(10)
            dsb = archr.arsenal.DataScoutBow(t)
            apb = archr.arsenal.angrProjectBow(t, dsb)
            partial_ld = apb.fire(return_loader=True, perform_relocations=False, load_debug_info=False)
            self._progress_callback(50)
            # is it smart to do this from the worker thread? who knows
            load_options, cfg_args = gui_thread_schedule(LoadBinary.run, (partial_ld,))
            partial_ld.close()
            if cfg_args is None:
                return

            # Create the project, load it, then record the image name on success
            proj = apb.fire(use_sim_procedures=True, load_options=load_options)
            self._progress_callback(95)
            inst.set_project(proj, cfg_args=cfg_args)


class LoadBinaryJob(Job):
    def __init__(self, fname, on_finish=None):
        super().__init__("Loading file", on_finish=on_finish)
        self.fname = fname

    def run(self, inst):
        self._progress_callback(5)
        try:
            partial_ld = cle.Loader(self.fname, perform_relocations=False, load_debug_info=False)
        except cle.CLECompatibilityError:
            # we don't support this binary format (at least for now)
            gui_thread_schedule(LoadBinary.binary_loading_failed, (self.fname,))
            return
        self._progress_callback(50)
        load_options, cfg_args = gui_thread_schedule(LoadBinary.run, (partial_ld, ))
        partial_ld.close()
        if cfg_args is None:
            return

        proj = angr.Project(self.fname, load_options=load_options)
        self._progress_callback(95)
        gui_thread_schedule(inst.set_project, (proj, cfg_args))
