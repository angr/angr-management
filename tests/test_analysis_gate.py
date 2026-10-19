"""
The gate the UI thread reads through while CFG recovery runs on the job thread: a reader waits for the recovery to
stop between its steps and keeps it stopped while it reads, gives up after a short wait, and the real CFG job stops
for it.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access,no-self-use

from __future__ import annotations

import os
import threading
import time
import unittest

import angr

from angrmanagement.data.instance import Instance
from angrmanagement.data.jobs import CFGGenerationJob
from angrmanagement.data.jobs.job import JobState
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.analysis_gate import AnalysisGate, gate_of
from angrmanagement.logic.jobmanager import JobManager
from angrmanagement.logic.threads import DirectExecutor

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")


class Analysis:
    """An analysis on its own thread that counts its steps and calls the gate's pause point after each."""

    def __init__(self, gate: AnalysisGate, steps: int | None = None, pauses: bool = True) -> None:
        self.gate = gate
        self.steps = 0
        self.limit = steps
        self.pauses = pauses
        self.started = threading.Event()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        with self.gate.running():
            self.started.set()
            while not self.stop.is_set() and (self.limit is None or self.steps < self.limit):
                self.steps += 1
                time.sleep(0.0005)
                if self.pauses:
                    self.gate.pause_point()

    def __enter__(self) -> Analysis:
        self.thread.start()
        assert self.started.wait(5)
        return self

    def __exit__(self, *args) -> None:
        self.stop.set()
        self.thread.join(5)
        assert not self.thread.is_alive()


class GateCase(unittest.TestCase):
    def setUp(self) -> None:
        self.saved_executor = GlobalInfo._executor
        GlobalInfo.executor = DirectExecutor()

    def tearDown(self) -> None:
        GlobalInfo.executor = self.saved_executor


class TestReaders(GateCase):
    def test_a_read_without_an_analysis_is_granted_at_once(self):
        gate = AnalysisGate()
        with gate.access() as granted:
            assert granted
            with gate.access() as again:
                assert again

    def test_the_analysis_stays_stopped_while_a_reader_reads(self):
        gate = AnalysisGate()
        with Analysis(gate) as analysis:
            for _ in range(5):
                with gate.access(timeout=5) as granted:
                    assert granted
                    before = analysis.steps
                    time.sleep(0.02)
                    assert analysis.steps == before
                # and it goes on once the read is done
                deadline = time.monotonic() + 5
                while analysis.steps == before and time.monotonic() < deadline:
                    time.sleep(0.001)
                assert analysis.steps > before

    def test_a_reader_that_reads_again_at_once_does_not_starve_the_analysis(self):
        gate = AnalysisGate()
        analysis = Analysis(gate, steps=200)
        with analysis:
            deadline = time.monotonic() + 30
            while analysis.thread.is_alive() and time.monotonic() < deadline:
                with gate.access(timeout=5) as granted:
                    assert granted
        assert analysis.steps == 200

    def test_a_reader_gives_up_when_the_analysis_does_not_stop(self):
        gate = AnalysisGate()
        with Analysis(gate, pauses=False):
            with gate.access(timeout=0.05) as granted:
                assert not granted
            # until the analysis stops again, the next readers do not wait
            start = time.monotonic()
            with gate.access(timeout=5) as granted:
                assert not granted
            assert time.monotonic() - start < 1

    def test_the_analysis_thread_itself_always_reads(self):
        gate = AnalysisGate()
        seen = []
        with gate.running(), gate.access(timeout=0) as granted:
            seen.append(granted)
        assert seen == [True]

    def test_an_analysis_waits_for_the_read_in_progress(self):
        gate = AnalysisGate()
        analysis = Analysis(gate, steps=1)
        with gate.access() as granted:
            assert granted
            analysis.thread.start()
            assert not analysis.started.wait(0.1)
        assert analysis.started.wait(5)
        analysis.thread.join(5)

    def test_a_deferred_read_runs_when_the_analysis_is_done(self):
        gate = AnalysisGate()
        calls = []
        with Analysis(gate):
            gate.retry_when_done(lambda: calls.append("done"))
            GlobalInfo.executor.process_pending()
            assert not calls
        GlobalInfo.executor.process_pending()
        assert calls == ["done"]

    def test_an_instance_without_a_gate_reads_freely(self):
        with gate_of(object()).access() as granted:
            assert granted


class TestCfgJobStops(GateCase):
    def test_the_cfg_job_stops_for_a_reader_and_the_reader_disassembles(self):
        instance = Instance()
        project = angr.Project(FAUXWARE, auto_load_libs=False)
        instance.project.am_obj = project
        instance.project.am_event()
        gate = instance.analysis_gate
        job_manager = JobManager(None)
        job = CFGGenerationJob(instance)
        steps = [0]
        added = job._on_cfb_object_added

        def counted(addr, obj):
            steps[0] += 1
            added(addr, obj)

        job._on_cfb_object_added = counted
        reads = 0
        try:
            job_manager.add_job(job)
            deadline = time.monotonic() + 120
            while job.state in (JobState.PENDING, JobState.RUNNING) and time.monotonic() < deadline:
                GlobalInfo.executor.process_pending()
                with gate.access(timeout=5) as granted:
                    if not granted or not gate.busy:
                        continue
                    before = steps[0]
                    # what the views do with the partial result: disassemble the functions found so far, with the
                    # capstone handle and the function graphs the recovery is using
                    for func in list(project.kb.functions.values())[:5]:
                        project.analyses.Disassembly(function=func)
                    assert steps[0] == before
                    reads += 1
            job_manager.join_all_jobs()
        finally:
            job_manager.quit()
        assert job.state is JobState.FINISHED
        assert reads > 0
        assert not gate.busy


if __name__ == "__main__":
    unittest.main()
