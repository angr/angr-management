from __future__ import annotations

import logging
import os
import tempfile
from typing import TYPE_CHECKING, Any

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

_l = logging.getLogger(name=__name__)


class FuzzerJob(InstanceJob):
    """A job that runs the angr fuzzer."""

    def __init__(
        self,
        instance: Instance,
        base_state,
        apply_fn_code: str,
        timeout: int,
        max_iterations: int | None,
        work_folder: str = "",
        on_finish=None,
    ) -> None:
        super().__init__("Fuzzing", instance, on_finish=on_finish)
        self._base_state = base_state
        self._apply_fn_code = apply_fn_code
        self._timeout = timeout
        self._max_iterations = max_iterations
        self._work_folder = work_folder
        self._interrupted = False
        # Thread-safe storage for corpus/solutions (updated by worker thread, read by GUI thread)
        self._current_corpus_items = []
        self._current_solutions_items = []

    def run(self, ctx: JobContext) -> dict[str, Any]:
        """Run the fuzzer job in a single thread."""
        from angr.rustylib.fuzzer import Fuzzer, OnDiskCorpus

        # Determine work folder
        if self._work_folder:
            work_folder = self._work_folder
            temp_dir = None
        else:
            temp_dir = tempfile.TemporaryDirectory(prefix="angr_fuzzer_")
            work_folder = temp_dir.name

        corpus_dir = os.path.join(work_folder, "corpus")
        solutions_dir = os.path.join(work_folder, "solutions")
        os.makedirs(corpus_dir, exist_ok=True)
        os.makedirs(solutions_dir, exist_ok=True)

        try:
            # Create initial corpus
            initial_corpus = [b"A" * 10, b"B" * 20, b"C" * 30]

            _l.info("Running fuzzer in single-threaded mode")
            _l.info("Using work folder: %s", work_folder)

            # Execute apply_fn code to define the function
            namespace = {
                "angr": __import__("angr"),
                "claripy": __import__("claripy"),
            }
            exec(self._apply_fn_code, namespace)
            apply_fn = namespace.get("apply_fn")

            if not apply_fn or not callable(apply_fn):
                _l.error("apply_fn is not defined or not callable")
                return {
                    "corpus_dir": corpus_dir,
                    "solutions_dir": solutions_dir,
                    "final_corpus_size": 0,
                    "final_solutions_size": 0,
                    "error": "apply_fn is not defined or not callable",
                }

            # Create OnDiskCorpus directly - fuzzer now supports it!
            corpus = OnDiskCorpus(corpus_dir)
            solutions = OnDiskCorpus(solutions_dir)

            # Add initial corpus items
            for item in initial_corpus:
                corpus.add(item)

            # Create fuzzer
            fuzzer = Fuzzer(
                base_state=self._base_state,
                corpus=corpus,
                solutions=solutions,
                apply_fn=apply_fn,
                timeout=self._timeout,
                seed=0,
            )

            # Progress callback that updates the job context
            # Note: Cannot store fuzzer reference due to thread safety (unsendable)
            # Instead, we query corpus/solutions in the worker thread and store as instance vars
            def progress_callback(stats, type_: str, _client_id: int) -> None:
                if self._interrupted:
                    return

                # Query corpus and solutions from disk
                # Fuzzer is writing directly to OnDiskCorpus now!
                try:
                    self._current_corpus_items = corpus.to_bytes_list()
                    self._current_solutions_items = solutions.to_bytes_list()
                except Exception as e:
                    _l.warning("Failed to query corpus/solutions: %s", e)

                # Update job context (this safely emits Qt signals)
                # Include event type in message for GUI to parse
                msg = (
                    f"Corpus: {stats.corpus_size}, "
                    f"Solutions: {stats.objective_size}, "
                    f"Execs: {stats.executions}, "
                    f"Speed: {stats.execs_per_sec_pretty}, "
                    f"Coverage: {stats.edges_hit}/{stats.edges_total}, "
                    f"Event: {type_}"
                )
                # Use executions as a rough progress indicator
                if self._max_iterations and self._max_iterations > 0:
                    percentage = min(100.0, (stats.executions / self._max_iterations) * 100.0)
                    ctx.set_progress(percentage, msg)
                else:
                    ctx.set_progress(0, msg)

            # Run fuzzer
            iterations = self._max_iterations if self._max_iterations and self._max_iterations > 0 else 1000
            _l.info("Starting fuzzer with %d iterations", iterations)

            fuzzer.run(progress_callback=progress_callback, iterations=iterations)

            # Get final sizes from on-disk corpus
            final_corpus_size = len(corpus)
            final_solutions_size = len(solutions)

            _l.info(
                "Fuzzer completed: corpus=%d, solutions=%d",
                final_corpus_size,
                final_solutions_size,
            )

            # Final progress update
            ctx.set_progress(
                100.0,
                f"Complete! Corpus: {final_corpus_size}, Solutions: {final_solutions_size}",
            )

            # Return results with on-disk corpus directories
            result = {
                "corpus_dir": corpus_dir,
                "solutions_dir": solutions_dir,
                "final_corpus_size": final_corpus_size,
                "final_solutions_size": final_solutions_size,
            }

            return result

        except Exception as e:
            _l.error("Fuzzer job failed with exception: %s", e)
            ctx.set_progress(100.0, f"Failed: {e}")
            return {
                "corpus_dir": corpus_dir,
                "solutions_dir": solutions_dir,
                "final_corpus_size": 0,
                "final_solutions_size": 0,
                "error": str(e),
            }
        finally:
            # Clean up temp dir if created
            if temp_dir is not None:
                try:
                    temp_dir.cleanup()
                except Exception as e:
                    _l.warning("Failed to cleanup temp directory: %s", e)

    def __repr__(self) -> str:
        return f"Fuzzing with {self._max_iterations or 'unlimited'} iterations"

    def cancel(self) -> None:
        """Called from GUI thread. Worker thread will check self._interrupted periodically and exit the job early."""
        self._interrupted = True

    @classmethod
    def create(
        cls,
        instance: Instance,
        base_state,
        apply_fn_code: str,
        timeout: int,
        max_iterations: int | None,
        work_folder: str = "",
        on_finish=None,
    ):
        """Create a fuzzer job."""
        return cls(
            instance, base_state, apply_fn_code, timeout, max_iterations,
            work_folder, on_finish=on_finish
        )
