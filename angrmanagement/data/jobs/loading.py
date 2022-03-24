
import cle
import angr
import archinfo
try:
    import archr
except ImportError:
    archr = None

from .job import Job
from ...logic.threads import gui_thread_schedule
from ...ui.dialogs import LoadBinary


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
            load_options, cfg_args, variable_recovery_args = gui_thread_schedule(LoadBinary.run, (partial_ld,))
            if cfg_args is None:
                return

            # Create the project, load it, then record the image name on success
            proj = apb.fire(use_sim_procedures=True, load_options=load_options)
            self._progress_callback(95)
            inst._reset_containers()
            inst.project = proj
            inst.project.am_event(cfg_args=cfg_args, variable_recovery_args=variable_recovery_args)


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
        new_load_options, cfg_args, variable_recovery_args = gui_thread_schedule(LoadBinary.run, (partial_ld, ))
        if cfg_args is None:
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
            inst.project.am_event(cfg_args=cfg_args, variable_recovery_args=variable_recovery_args)
        gui_thread_schedule(callback, ())
