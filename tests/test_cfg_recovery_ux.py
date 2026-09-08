# pylint:disable=missing-class-docstring,wrong-import-order,protected-access
from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from typing import TYPE_CHECKING

import angr
from common import AngrManagementTestCase, test_location
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QMessageBox

from angrmanagement.data.jobs import CFGGenerationJob
from angrmanagement.data.jobs.job import JobState
from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.ui.views import DisassemblyView
from angrmanagement.ui.widgets.qblock import QLinearBlock

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase

    from angrmanagement.data.instance import Instance


def assert_no_overlap(cfb) -> None:
    """
    Assert that no two objects in the blanket overlap.
    """
    prev_key, prev_end = None, None
    for key, obj in cfb._blanket.items():
        size = obj.size if isinstance(getattr(obj, "size", None), int) else None
        if prev_end is not None:
            assert key >= prev_end, f"object at {key:#x} overlaps the object at {prev_key:#x} (ends at {prev_end:#x})"
        prev_key, prev_end = key, key + max(size or 1, 1)


class CfgRecoveryUxTestCase(AngrManagementTestCase):
    """
    Base class: loads fauxware without triggering the automatic analysis, so that tests fully control CFG generation.
    """

    binary = os.path.join(test_location, "x86_64", "fauxware")

    def setUp(self):
        super().setUp()
        # suppress the automatic analysis that project.am_event() would trigger
        self.main.workspace.run_analysis = lambda *args, **kwargs: None
        self.proj = angr.Project(self.binary, auto_load_libs=False)
        self.main.workspace.main_instance.project.am_obj = self.proj
        self.main.workspace.main_instance.project.am_event()
        self.main.workspace.job_manager.join_all_jobs()

    @property
    def instance(self) -> Instance:
        return self.main.workspace.main_instance

    @property
    def kb(self) -> KnowledgeBase:
        kb = self.instance.kb
        assert kb is not None
        return kb

    @property
    def cfg_container(self) -> ObjectContainer:
        cfg = self.instance.cfg
        assert isinstance(cfg, ObjectContainer)
        return cfg

    @property
    def cfb_container(self) -> ObjectContainer:
        cfb = self.instance.cfb
        assert isinstance(cfb, ObjectContainer)
        return cfb

    def disassembly_view(self) -> DisassemblyView:
        view = self.main.workspace.view_manager.first_view_in_category("disassembly")
        assert isinstance(view, DisassemblyView)
        return view

    def run_cfg_job(self, cancel_on_first_progress: bool = False, cfg_args: dict | None = None) -> CFGGenerationJob:
        """
        Run a CFG generation job through the analysis manager plumbing, optionally simulating a user cancellation at
        the first progress notification from CFGFast.
        """
        workspace = self.main.workspace
        am = workspace.analysis_manager
        job = CFGGenerationJob(
            workspace.main_instance,
            on_finish=am._on_cfg_generated,
            on_cfb_available=am._on_cfg_recovery_started,
            **(cfg_args or {}),
        )

        if cancel_on_first_progress:
            orig_cb = job._progress_callback

            def cancelling_cb(ctx, percentage, text=None, cfg=None):
                if cfg is not None and job.state == JobState.RUNNING:
                    workspace.job_manager.cancel_job(job)
                orig_cb(ctx, percentage, text=text, cfg=cfg)

            job._progress_callback = cancelling_cb

        workspace.job_manager.add_job(job)
        workspace.job_manager.join_all_jobs()
        return job

    @staticmethod
    def full_reference_functions() -> set[int]:
        proj = angr.Project(CfgRecoveryUxTestCase.binary, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        return set(proj.kb.functions)


class TestGracefulCancel(CfgRecoveryUxTestCase):
    def test_cancel_produces_finalized_partial_cfg(self):
        workspace = self.main.workspace
        job = self.run_cfg_job(cancel_on_first_progress=True)

        assert job.state == JobState.CANCELLED
        # the partial results were published despite the cancellation
        assert not self.cfg_container.am_none
        assert not self.cfb_container.am_none
        assert len(workspace.main_instance.cfg.graph) > 0
        # the unprocessed frontier and the resume state were captured for resuming
        assert len(workspace.main_instance.cfg_resume_frontier) > 0
        assert workspace.main_instance.cfg_resume_state is not None
        assert len(workspace.main_instance.cfg_resume_state.jobs) > 0
        # the recovery was truncated: some functions of the full run are missing
        assert self.full_reference_functions() - set(self.kb.functions)


class TestResume(CfgRecoveryUxTestCase):
    def test_resume_from_address(self):
        workspace = self.main.workspace
        self.run_cfg_job(cancel_on_first_progress=True)

        missing = sorted(self.full_reference_functions() - set(self.kb.functions))
        assert missing
        seed = missing[0]

        assert workspace.can_resume_cfg_recovery(seed)
        workspace.resume_cfg_recovery(seed)
        workspace.job_manager.join_all_jobs()

        assert seed in self.kb.functions

    def test_full_resume_converges(self):
        workspace = self.main.workspace
        self.run_cfg_job(cancel_on_first_progress=True)

        assert workspace.can_resume_cfg_recovery()
        workspace.resume_cfg_recovery_full()
        workspace.job_manager.join_all_jobs()

        # resuming with the captured resume state reproduces the exact function set of an uninterrupted run
        assert set(self.kb.functions) == self.full_reference_functions()

    def test_full_resume_after_strict_resume_converges(self):
        # a strict resume-from-address job must not clobber the captured resume state; a full resume afterwards
        # still converges to the uninterrupted function set
        workspace = self.main.workspace
        self.run_cfg_job(cancel_on_first_progress=True)
        state = workspace.main_instance.cfg_resume_state
        assert state is not None

        missing = sorted(self.full_reference_functions() - set(self.kb.functions))
        assert missing
        workspace.resume_cfg_recovery(missing[0])
        workspace.job_manager.join_all_jobs()

        # the strict resume completed but the captured resume state is preserved
        assert workspace.main_instance.cfg_resume_state is state

        workspace.resume_cfg_recovery_full()
        workspace.job_manager.join_all_jobs()
        assert set(self.kb.functions) == self.full_reference_functions()
        # the full resume consumed the state
        assert workspace.main_instance.cfg_resume_state is None

    def test_can_resume_enablement(self):
        workspace = self.main.workspace

        # no CFG yet: resume is not possible
        assert not workspace.can_resume_cfg_recovery()

        self.run_cfg_job()
        assert not self.cfg_container.am_none

        # a complete CFG exists and no job is running: full resume is possible
        assert workspace.can_resume_cfg_recovery()
        # an address that is already part of the CFG cannot be used as a resume point
        entry = self.proj.entry
        assert workspace.main_instance.cfg.get_any_node(entry) is not None
        assert not workspace.can_resume_cfg_recovery(entry)
        # an unmapped address cannot be used as a resume point
        assert not workspace.can_resume_cfg_recovery(0x100)


class TestEntryPointAtRecoveryStart(CfgRecoveryUxTestCase):
    def test_on_cfg_recovery_started_shows_entry_in_linear_view(self):
        workspace = self.main.workspace
        cfb = self.proj.analyses.CFB(exclude_region_types={"kernel", "tls"})

        assert not workspace._first_cfg_generation_callback_completed
        workspace.on_cfg_recovery_started(cfb)

        assert not self.cfb_container.am_none
        disasm_view = self.disassembly_view()
        # the linear viewer is displayed and the entry point is the current location
        assert disasm_view._current_view is disasm_view._linear_viewer
        assert disasm_view.jump_history.current == self.proj.entry
        # the programmatic navigation was not recorded as a user navigation
        assert not workspace._user_navigated_during_cfg


class TestLiveViewportUpdates(CfgRecoveryUxTestCase):
    def test_objects_added_in_viewport_triggers_refresh(self):
        workspace = self.main.workspace
        self.run_cfg_job()

        disasm_view = workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_linear_viewer()
        entry = self.proj.entry
        disasm_view.jump_to(entry)
        QTest.qWait(100)

        addr_range = disasm_view._linear_viewer.visible_addr_range()
        assert addr_range is not None
        assert addr_range[0] <= entry < addr_range[1]

        refreshes = []
        disasm_view._linear_viewer.refresh_objects = lambda: refreshes.append(True)

        # an object within the viewport triggers a refresh
        disasm_view._last_objects_added_refresh = 0.0
        disasm_view._on_cfb_event(objects_added=[(entry, SimpleNamespace(size=4))])
        QTest.qWait(200)
        assert refreshes

        # an object far outside the viewport does not
        refreshes.clear()
        disasm_view._last_objects_added_refresh = 0.0
        disasm_view._on_cfb_event(objects_added=[(addr_range[1] + 0x10000, SimpleNamespace(size=4))])
        QTest.qWait(200)
        assert not refreshes

        # an object without a size must not crash the intersection check
        disasm_view._refresh_linear_viewer_on_objects_added([(entry, SimpleNamespace(size=None))])


class TestBlanketNonOverlap(CfgRecoveryUxTestCase):
    def test_blanket_nonoverlapping_after_completed_recovery(self):
        workspace = self.main.workspace
        self.run_cfg_job()
        assert not self.cfb_container.am_none
        assert_no_overlap(workspace.main_instance.cfb)

    def test_blanket_nonoverlapping_after_cancelled_recovery(self):
        workspace = self.main.workspace
        self.run_cfg_job(cancel_on_first_progress=True)
        assert not self.cfb_container.am_none
        assert_no_overlap(workspace.main_instance.cfb)


class TestGraphViewNormalization(CfgRecoveryUxTestCase):
    def test_graph_view_blocks_are_normalized_for_unnormalized_functions(self):
        """
        During CFG recovery the kb functions are not normalized yet (normalization only happens in post-analysis), so
        a function displayed in the graph view may contain overlapping blocks: a block that is also a jump target
        inside a longer fall-through block is shown twice (e.g. blocks 0x1404fee4a and 0x1404fee4c of OUTLOOK.EXE).
        Reproduce that state with normalize=False and assert that the graph view renders non-overlapping blocks.
        """
        workspace = self.main.workspace
        self.run_cfg_job(cfg_args={"normalize": False})

        func = self.kb.functions.function(name="authenticate")
        assert func is not None
        assert not func.normalized
        # the raw (un-normalized) function graph does contain overlapping blocks
        raw_spans = sorted((b.addr, b.size) for b in func.blocks if b.size)
        assert any(a1 + s1 > a2 for (a1, s1), (a2, _s2) in zip(raw_spans, raw_spans[1:], strict=False)), (
            "test premise broken: the un-normalized function has no overlapping blocks"
        )

        disasm_view = workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_disasm_graph()
        disasm_view.display_function(func)

        # the graph view must not display overlapping blocks
        function_graph = disasm_view._flow_graph.function_graph
        assert function_graph is not None
        supergraph = function_graph.supergraph
        spans = sorted(
            (cfg_node.addr, cfg_node.size) for node in supergraph.nodes for cfg_node in node.cfg_nodes if cfg_node.size
        )
        for (a1, s1), (a2, _s2) in zip(spans, spans[1:], strict=False):
            assert a1 + s1 <= a2, f"overlapping blocks rendered in the graph view: {a1:#x}+{s1:#x} overlaps {a2:#x}"


class TestDisplayBlocklessFunction(CfgRecoveryUxTestCase):
    def test_display_blockless_function_does_not_crash(self):
        """
        During CFG recovery, kb.functions contains functions that were created at call-processing time but whose
        bodies have not been traced yet (no blocks). Displaying one in the graph view used to dereference a stale
        entry_block widget whose C++ object had been deleted by the preceding scene reset (RuntimeError: Internal
        C++ object (QGraphBlock) already deleted).
        """
        workspace = self.main.workspace
        self.run_cfg_job()

        disasm_view = workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_disasm_graph()

        # display a real function first so that entry_block is populated with a widget that the next scene reset
        # will delete
        main_func = self.kb.functions.function(name="main")
        assert main_func is not None
        disasm_view.display_function(main_func)
        assert disasm_view._flow_graph.entry_block is not None

        # a block-less function, like the ones CFGFast creates at call sites before tracing their bodies
        empty_func = self.kb.functions.function(addr=0x400700, create=True)
        assert empty_func is not None
        assert not list(empty_func.blocks)
        disasm_view.linear_viewer.resize(800, 600)
        disasm_view.display_function(empty_func)  # must not raise
        assert disasm_view._flow_graph.entry_block is None
        # instead of an empty graph, the linear view is displayed at the function's address (without changing the
        # user's graph-view preference)
        assert disasm_view._current_view is disasm_view.linear_viewer
        addr_range = disasm_view.linear_viewer.visible_addr_range()
        assert addr_range is not None
        assert addr_range[0] <= empty_func.addr < addr_range[1]

        # displaying a real function again restores the preferred graph view and a live entry block
        disasm_view.display_function(main_func)
        assert disasm_view._current_view is disasm_view._flow_graph
        assert disasm_view._flow_graph.entry_block is not None


class TestLinearViewNormalization(CfgRecoveryUxTestCase):
    def test_linear_view_renders_no_duplicate_instructions(self):
        """
        During CFG recovery, a jump-target block streamed after its enclosing fall-through block trims the blanket
        entry (e.g. [0x4006e6, 0x4006eb) + [0x4006eb, ...)), but QLinearBlock used to render the instruction list of
        the un-normalized function's block (disasm.block_to_insn_addrs[0x4006e6] = 3 instructions), so the trailing
        instructions were displayed twice - once in each block (the OUTLOOK.EXE 0x1404fee4a/0x1404fee4c case).
        """
        workspace = self.main.workspace
        self.run_cfg_job(cfg_args={"normalize": False})
        proj = self.proj

        func = self.kb.functions.function(name="authenticate")
        assert func is not None and not func.normalized

        # recreate the mid-recovery streaming order: the big fall-through block first, then the jump-target block
        # that starts inside it; the blanket trims the big entry to [0x4006e6, 0x4006eb)
        big_addr, small_addr = 0x4006E6, 0x4006EB
        cfb = workspace.main_instance.cfb
        cfb.add_obj(big_addr, proj.factory.block(big_addr))
        cfb.add_obj(small_addr, proj.factory.block(small_addr))
        assert cfb[big_addr].size == small_addr - big_addr

        disasm_view = workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_linear_viewer()
        viewer = disasm_view.linear_viewer
        viewer.resize(800, 600)
        viewer.navigate_to_addr(big_addr)
        viewer.refresh_objects()

        rendered = {
            addr: qobj for addr, qobj in viewer.objects.items() if isinstance(qobj, QLinearBlock) and qobj.isVisible()
        }
        assert big_addr in rendered and small_addr in rendered

        # every rendered instruction stays within its blanket entry's span...
        for addr, qobj in rendered.items():
            span = cfb[addr].size
            for insn_addr in qobj.addr_to_insns:
                assert addr <= insn_addr < addr + span, (
                    f"block {addr:#x} (span {span:#x}) renders out-of-span instruction {insn_addr:#x}"
                )
        # ... and no instruction is rendered twice
        seen: dict[int, int] = {}
        for addr, qobj in rendered.items():
            for insn_addr in qobj.addr_to_insns:
                assert insn_addr not in seen, (
                    f"instruction {insn_addr:#x} rendered by both block {seen[insn_addr]:#x} and block {addr:#x}"
                )
                seen[insn_addr] = addr


class TestAskBeforeNavigating(CfgRecoveryUxTestCase):
    def test_no_prompt_without_user_navigation(self):
        questions = []
        orig_question = QMessageBox.question
        QMessageBox.question = lambda *args, **kwargs: questions.append(args) or QMessageBox.StandardButton.Yes
        try:
            self.run_cfg_job()
        finally:
            QMessageBox.question = orig_question

        # no prompt: the view navigated to main and switched to the graph view
        assert not questions
        disasm_view = self.disassembly_view()
        assert disasm_view._current_view is disasm_view._flow_graph
        main_func = self.kb.functions.function(name="main")
        assert main_func is not None
        assert disasm_view.jump_history.current == main_func.addr

    def test_prompt_after_user_navigation_can_decline(self):
        workspace = self.main.workspace

        # pretend the user navigated during the job by forcing the flag through the completion path
        questions = []
        orig_question = QMessageBox.question
        QMessageBox.question = lambda *args, **kwargs: questions.append(args) or QMessageBox.StandardButton.No

        orig_started = workspace.on_cfg_recovery_started

        def started_and_navigate(cfb):
            orig_started(cfb)
            workspace._user_navigated_during_cfg = True

        workspace.on_cfg_recovery_started = started_and_navigate
        try:
            self.run_cfg_job()
        finally:
            QMessageBox.question = orig_question
            workspace.on_cfg_recovery_started = orig_started

        # the user was asked and declined: the view stays in the linear viewer
        assert questions
        disasm_view = self.disassembly_view()
        assert disasm_view._current_view is disasm_view._linear_viewer


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
