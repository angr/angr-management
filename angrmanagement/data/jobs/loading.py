
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
            load_options, cfg_args = gui_thread_schedule(LoadBinary.run, (partial_ld,))
            partial_ld.close()
            if cfg_args is None:
                return

            # Create the project, load it, then record the image name on success
            proj = apb.fire(use_sim_procedures=True, load_options=load_options)
            self._progress_callback(95)
            inst._reset_containers()
            inst.project = proj
            inst.project.am_event(cfg_args=cfg_args)


class LoadBinaryJob(Job):
    def __init__(self, fname, on_finish=None):
        super().__init__("Loading file", on_finish=on_finish)
        self.fname = fname

    def run(self, inst):
        self._progress_callback(5)

        partial_ld = None
        try:
            # Try automatic loading
            partial_ld = cle.Loader(self.fname, perform_relocations=False, load_debug_info=False)
        except cle.CLECompatibilityError:
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
        load_options, cfg_args = gui_thread_schedule(LoadBinary.run, (partial_ld, ))
        partial_ld.close()
        if cfg_args is None:
            return

        proj = angr.Project(self.fname, load_options=load_options)
        self._progress_callback(95)
        def callback():
            inst._reset_containers()
            inst.project.am_obj = proj
            inst.project.am_event(cfg_args=cfg_args)
        gui_thread_schedule(callback, ())
