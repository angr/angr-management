from __future__ import annotations

import logging
import multiprocessing
import subprocess
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import TYPE_CHECKING

import angr

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

from .job import InstanceJob

_l = logging.getLogger(name=__name__)


def _process_binary(
    target_project: angr.Project, binary_path: str, arch_name: str, instruction_endness: str
) -> tuple[str, bool, str | None, dict]:
    """
    Process a single binary file for bindiff analysis.
    Returns tuple of (binary_path, success, error_message, matches)
    This function runs in a separate process.
    """
    try:
        main_opts = {"arch": arch_name, "endness": instruction_endness}
        base_project = angr.Project(binary_path, main_opts=main_opts)

        cfg = base_project.analyses.CFG(
            show_progressbar=False,
            normalize=True,
            resolve_indirect_jumps=True,
            detect_tail_calls=True,
        )

        bindiff = target_project.analyses.BinDiff(
            base_project,
            cfg_a=target_project.kb.cfgs.get_most_accurate(),
            cfg_b=base_project.kb.cfgs.get_most_accurate(),
        )

        out = {}
        for a0, a1 in bindiff.function_matches:
            # func_0 = target_project.kb.functions.get_by_addr(a0)
            func_1 = base_project.kb.functions.get_by_addr(a1)
            if (
                func_1.is_default_name
                or func_1.name.startswith("sub_")
                or "unknown" in func_1.name.lower()
                or "unresolve" in func_1.name.lower()
            ):
                continue
            out[a0] = func_1.name
        return (binary_path, True, None, out)

    except angr.errors.AngrCFGError as e:
        # Ignore empty regions as some .o files may contain no code
        if "Regions are empty" in str(e):
            return (binary_path, True, None, {})
        return (binary_path, False, str(e), None)
    except Exception as e:
        return (binary_path, False, str(e), None)


class BindiffMatchingJob(InstanceJob):
    """
    Describes a job for finding matches via bindiff analysis using multiprocessing.
    """

    def __init__(self, instance: Instance, filenames: list[str], on_finish=None, on_results=None) -> None:
        super().__init__("Finding matches via bindiff", instance, on_finish=on_finish)
        self.filenames = filenames
        self.on_results = on_results

    def run(self, ctx: JobContext) -> None:
        binaries_to_process = []
        temp_dirs = []

        matches_per_file = {}

        for filename in self.filenames:
            if filename.endswith(".a"):
                tmpdir = tempfile.mkdtemp()
                temp_dirs.append(tmpdir)
                try:
                    subprocess.check_call(
                        ["ar", "x", Path(filename).absolute()],
                        cwd=tmpdir,
                    )
                    tmpdir_path = Path(tmpdir)
                    object_files = list(tmpdir_path.glob("*.o"))
                    binaries_to_process.extend([(filename, str(f)) for f in object_files])
                    matches_per_file[filename] = {}
                    _l.info("Extracted %d object files from %s", len(object_files), filename)
                except Exception:
                    _l.warning("Failed to unarchive %s using ar command. Is ar installed?", filename)
            else:
                binaries_to_process.append((filename, filename))
                matches_per_file[filename] = {}

        if not binaries_to_process:
            ctx.set_progress(1.0, "No binaries to process")
            return

        arch_name = self.instance.project.arch.name
        instruction_endness = self.instance.project.arch.instruction_endness

        max_workers = min(max(multiprocessing.cpu_count() - 1, 1), len(binaries_to_process))
        _l.info("Processing %d binaries with %d workers", len(binaries_to_process), max_workers)

        total_binaries = len(binaries_to_process)
        completed = 0
        failed = 0

        num_found_matches = 0
        num_conflicts = 0

        try:
            # Process binaries in parallel
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                future_to_binary = {
                    executor.submit(
                        _process_binary, self.instance.project.am_obj, binary, arch_name, instruction_endness
                    ): (original_file, binary)
                    for original_file, binary in binaries_to_process
                }

                for future in as_completed(future_to_binary):
                    original_file, binary = future_to_binary[future]
                    try:
                        binary_path, success, error_msg, output = future.result()
                        if success:
                            completed += 1
                            _l.debug("Successfully processed %s", Path(binary_path).name)
                            if output:
                                existing_matches = matches_per_file[original_file]
                                for addr, name in output.items():
                                    if addr in existing_matches:
                                        num_conflicts += 1
                                    else:
                                        existing_matches[addr] = name
                                        num_found_matches += 1
                        else:
                            failed += 1
                            _l.warning("Failed to process %s: %s", Path(binary_path).name, error_msg)
                    except Exception as e:
                        failed += 1
                        _l.exception("Exception processing %s: %s", Path(binary).name, e)

                    progress = (completed + failed) / total_binaries * 100.0
                    ctx.set_progress(
                        progress,
                        f"{completed + failed}/{total_binaries} binaries ({failed} failed); Found {num_found_matches} matched functions; {num_conflicts} conflicts",
                    )

        finally:
            # Clean up temporary directories
            import shutil

            for tmpdir in temp_dirs:
                try:
                    shutil.rmtree(tmpdir)
                except Exception as e:
                    _l.warning("Failed to clean up temporary directory %s: %s", tmpdir, e)

        ctx.set_progress(1.0, f"Bindiff matching complete: {completed} succeeded, {failed} failed")
        _l.info("Bindiff matching complete: %d succeeded, %d failed", completed, failed)

        # Run the on_finish callback
        if self.on_results:
            self.on_results(matches_per_file)

    def __repr__(self) -> str:
        return "BindiffMatchingJob"
