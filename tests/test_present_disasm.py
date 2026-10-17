"""
The disassembly presenter on fauxware, without a window: jumps and the jump history, levels, display options, the
linear view's objects, find, menus, keys, and the render models the terminal draws.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use

from __future__ import annotations

import os
import unittest
from types import SimpleNamespace
from typing import Any

import angr

from angrmanagement.data.function_graph import FunctionGraph
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.headless_workspace import HeadlessWorkspace
from angrmanagement.logic.ui_services import HeadlessServices
from angrmanagement.present.block_tree.disasm_nodes import InsnNode, LabelNode
from angrmanagement.present.disasm import (
    DISASM_COMMANDS,
    DisasmPresenter,
    DisassemblyLevel,
    LinearBlock,
    disassembly_keymap,
    register_disasm_commands,
)
from angrmanagement.present.disasm_controls import HeadlessDisasmView
from angrmanagement.present.menus import walk_entries

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")


def set_services(services: Any) -> None:
    GlobalInfo.ui_services = services  # pyright: ignore[reportAttributeAccessIssue]


class PromptServices(HeadlessServices):
    """Headless services that answer every prompt with a fixed text."""

    def __init__(self, answer: str | None) -> None:
        super().__init__()
        self.answer = answer
        self.prompts: list[str] = []

    def prompt_text(self, title: str, label: str, default: str = "") -> str | None:
        self.prompts.append(title)
        return self.answer

    def ask_form_async(self, form: Any, callback: Any) -> None:
        """Type the answer in the form's first field; OK only if the form's check accepts it."""
        self.prompts.append(form.title)
        if self.answer is None:
            callback(None)
            return
        values = {**form.initial_values(), form.fields[0].key: self.answer}
        callback(values if form.checked(values).ok else None)


class FauxwareDisasmCase(unittest.TestCase):
    """A headless workspace with fauxware, its CFG and its CFB, and a disassembly view that draws nothing."""

    project: angr.Project

    @classmethod
    def setUpClass(cls):
        cls.project = angr.Project(FAUXWARE, auto_load_libs=False)
        cls.cfg = cls.project.analyses.CFGFast(normalize=True, data_references=True, cross_references=True)
        # the prototypes the function headers show, as the default analyses recover them
        analyses: Any = cls.project.analyses
        analyses.CompleteCallingConventions(recover_variables=True)
        cls.cfb = analyses.CFB(kb=cls.project.kb)

    def setUp(self):
        self.workspace: Any = HeadlessWorkspace(auto_analyze=False)
        self.instance: Any = self.workspace.main_instance
        self.instance.project.am_obj = self.project
        self.instance.project.am_event()
        self.instance.cfg.am_obj = self.cfg.model
        self.instance.cfg.am_event()
        self.instance.cfb.am_obj = self.cfb
        self.instance.cfb.am_event()
        self.saved_services = GlobalInfo._ui_services
        set_services(HeadlessServices())
        self.view: Any = HeadlessDisasmView(self.workspace, self.instance)
        self.presenter: Any = self.view.presenter
        self.main = self.project.kb.functions["main"]
        self.insns = sorted(a for b in self.main.blocks for a in b.instruction_addrs)

    def tearDown(self):
        self.view.close()
        set_services(self.saved_services)
        self.workspace.job_manager.quit()


class TestJumps(FauxwareDisasmCase):
    def test_repeated_jump_to_stays_on_target(self):
        target = self.insns[len(self.insns) // 2]
        for _ in range(3):
            assert self.presenter.jump_to(target)
            assert self.presenter.function.am_obj is self.main
            assert self.presenter.infodock.selected_insns == {target}
            # the graph was asked to show the target, not the function head
            assert self.view.flow_graph.shown_insn == target
            assert self.view.flow_graph.focus == self.view.flow_graph.position_of(target)
            # the function head must not be recorded after the jump target
            assert self.presenter.jump_history.history[-1] == target

    def test_display_function_via_container_still_works(self):
        other = next(f for f in self.project.kb.functions.values() if f is not self.main and f.block_addrs_set)
        self.presenter.function = other
        shown: Any = self.presenter.function
        assert shown.am_obj is other
        assert self.view.flow_graph.function_graph.function is other

    def test_jump_to_none_is_rejected(self):
        assert self.presenter.jump_to(None) is False
        assert self.presenter.jump_to(0xDEAD_0000_0000) is False

    def test_back_and_forward(self):
        auth = self.project.kb.functions["authenticate"]
        self.presenter.display_function(self.main)
        self.presenter.jump_to(auth.addr)
        assert self.presenter.function.am_obj is auth
        self.presenter.jump_back()
        assert self.presenter.function.am_obj is self.main
        self.presenter.jump_forward()
        assert self.presenter.function.am_obj is auth
        menu = self.presenter.history_menu()
        assert [e.text for _, e in walk_entries(menu)][0].startswith("authenticate")

    def test_jump_to_data_switches_to_linear(self):
        self.presenter.display_function(self.main)
        # the "Username: " string is data in .rodata, outside every function
        assert self.presenter.jump_to(0x400915)
        assert self.presenter.is_linear
        assert self.presenter.infodock.selected_labels or self.view.linear_viewer.offset is not None

    def test_resolve_address(self):
        assert self.presenter.resolve_address("main") == self.main.addr
        assert self.presenter.resolve_address("40071d") == 0x40071D
        assert self.presenter.resolve_address("0x40071d") == 0x40071D
        assert self.presenter.resolve_address("no such thing") is None

    def test_jumpto_prompt(self):
        services = PromptServices("authenticate")
        set_services(services)
        self.presenter.popup_jumpto_dialog()
        assert services.prompts == ["Jump to address"]
        assert self.presenter.function.am_obj is self.project.kb.functions["authenticate"]
        # the box refuses what is not an address, as the Qt JumpTo dialog does
        set_services(PromptServices("no such function"))
        self.presenter.popup_jumpto_dialog()
        assert self.presenter.function.am_obj is self.project.kb.functions["authenticate"]


class TestLevelsAndOptions(FauxwareDisasmCase):
    def test_level_switching(self):
        levels = []
        self.presenter.level_changed.connect(levels.append)
        self.presenter.display_function(self.main)
        assert self.view.flow_graph.disasm._include_ir is False
        self.presenter.set_disassembly_level_lifter_ir()
        assert self.presenter.disassembly_level is DisassemblyLevel.LifterIR
        assert self.view.flow_graph.disasm._include_ir is True
        self.presenter.display_function(self.project.kb.functions["authenticate"])
        self.presenter.set_disassembly_level_ail()
        assert isinstance(self.view.flow_graph.disasm, angr.analyses.decompiler.clinic.Clinic)
        assert levels == [DisassemblyLevel.LifterIR, DisassemblyLevel.AIL]

    def test_show_address_toggles_the_address_text(self):
        self.presenter.display_function(self.main)
        entry = self.view.flow_graph.doc.blocks[self.view.flow_graph.doc.entry]
        assert any(line.text.startswith("0040071d") for line in entry.lines)
        self.presenter.toggle_show_address()
        entry = self.view.flow_graph.doc.blocks[self.view.flow_graph.doc.entry]
        assert not any("0040071d" in line.text for line in entry.lines)
        assert any(line.text.startswith("push") for line in entry.lines)
        self.presenter.toggle_show_address(True)
        assert self.presenter.show_address

    def test_toggles_flip_their_options(self):
        for toggle, getter in [
            (self.presenter.toggle_show_variable, "show_variable"),
            (self.presenter.toggle_show_variable_identifier, "show_variable_identifier"),
            (self.presenter.toggle_show_minimap, "show_minimap"),
            (self.presenter.toggle_smart_highlighting, "smart_highlighting"),
            (self.presenter.toggle_show_exception_edges, "show_exception_edges"),
        ]:
            before = getattr(self.presenter, getter)
            toggle()
            assert getattr(self.presenter, getter) is (not before), getter
        menu = self.presenter.options_menu()
        assert [e.text for _, e in walk_entries(menu)] == [
            "Show minimap",
            "Smart highlighting",
            "Show address",
            "Show variable",
            "Show variable identifiers",
            "Show exception transition edges",
        ]

    def test_graph_and_linear(self):
        self.presenter.display_function(self.main)
        assert not self.presenter.is_linear
        self.presenter.toggle_disasm_view()
        assert self.presenter.is_linear
        assert not self.view.flow_graph.visible and self.view.linear_viewer.visible
        self.presenter.toggle_disasm_view()
        assert not self.presenter.is_linear


class TestGraphDoc(FauxwareDisasmCase):
    def test_main_has_the_blocks_of_its_supergraph(self):
        doc, _ = self.presenter.graph_doc(FunctionGraph(self.main))
        supergraph = FunctionGraph(self.main).supergraph
        assert sorted(b.addr for b in doc.blocks.values()) == sorted(n.addr for n in supergraph.nodes())
        entry = doc.blocks[doc.entry]
        assert entry.addr == self.main.addr
        texts = [line.text for line in entry.lines]
        assert texts[2] == "int main(long long a0, long long a1)"
        assert texts[4:6] == ["arg_0 @ rdi", "arg_1 @ rsi"]
        assert texts[7].split() == ["0040071d", "push", "rbp"]
        assert texts[8].split() == ["0040071e", "mov", "rbp,", "rsp"]
        # every block is placed, apart from the others
        boxes = [(*doc.layout[k], *doc.sizes[k]) for k in doc.blocks]
        for i, (x, y, w, h) in enumerate(boxes):
            for x2, y2, w2, h2 in boxes[i + 1 :]:
                assert x + w <= x2 or x2 + w2 <= x or y + h <= y2 or y2 + h2 <= y
        assert len(doc.edges) == supergraph.number_of_edges()
        for edge in doc.edges:
            # orthogonal segments, ending just above the destination block
            for (ax, ay), (bx, by) in zip(edge.points, edge.points[1:], strict=False):
                assert ax == bx or ay == by
            dst = next(k for k in doc.blocks if k.addr == edge.dst_addr)
            assert edge.points[-1][1] == doc.layout[dst][1] - 1

    def test_operand_spans_belong_to_their_operands(self):
        doc, _ = self.presenter.graph_doc(FunctionGraph(self.main))
        entry = doc.blocks[doc.entry]
        row = entry.rows_of(0x40071E)[0]
        insn = entry.nodes[row]
        assert isinstance(insn, InsnNode)
        line = entry.lines[row]
        start = line.text.index("rsp")
        assert line.node_at(start) is insn.operands[1]
        assert line.node_at(line.text.index("mov")) is insn

    def test_selection_restyles_the_line(self):
        self.presenter.display_function(self.main)
        graph = self.view.flow_graph
        self.presenter.infodock.select_instruction(0x40071E)
        key = graph.doc.insn_block[0x40071E]
        row = graph.doc.blocks[key].rows_of(0x40071E)[0]
        styles = {span.style for span in graph.doc.blocks[key].lines[row].spans}
        assert any("disasm_view_node_instruction_selected_background_color" in s for s in styles)

    def test_levels_of_detail(self):
        self.presenter.display_function(self.main)
        self.workspace.set_comment(self.insns[3], "a comment")
        graph = self.view.flow_graph
        graph.refresh()

        def entry_text():
            return [line.text for line in graph.block_lines(graph.doc.blocks[graph.doc.entry])]

        assert any("; a comment" in t for t in entry_text())
        graph.set_detail(1)
        assert not any("; a comment" in t for t in entry_text())
        assert any(t.startswith("0040071d") for t in entry_text())
        graph.set_detail(2)
        assert not any("0040071d" in t for t in entry_text())
        graph.set_detail(3)
        assert entry_text() == [graph.doc.blocks[graph.doc.entry].header]
        graph.set_detail(0)
        assert any("; a comment" in t for t in entry_text())


class TestLinear(FauxwareDisasmCase):
    def test_disassembly_level_change(self):
        self.presenter.display_linear_viewer()
        self.presenter.display_function(self.main)
        objects = self.view.linear_viewer.objects
        assert self.main.addr in objects
        assert isinstance(objects[self.main.addr], LinearBlock)
        assert objects[self.main.addr].level is DisassemblyLevel.MachineCode
        self.presenter.set_disassembly_level_lifter_ir()
        self.presenter.display_function(self.main)
        assert objects is not self.view.linear_viewer.objects or self.main.addr in self.view.linear_viewer.objects
        assert self.view.linear_viewer.objects[self.main.addr].level is DisassemblyLevel.LifterIR

    def test_block_lines_and_cache(self):
        self.presenter.display_linear_viewer()
        self.presenter.display_function(self.main)
        lines = [line.text for _node, line in self.view.linear_viewer.lines()]
        joined = "\n".join(lines)
        assert "int main(long long a0, long long a1)" in joined
        first_insn = next(t for t in lines if t.startswith("0040071d"))
        assert first_insn.split() == ["0040071d", "push", "rbp"]
        assert any(t.split() == ["0040073e", "loc_0x40073e:"] for t in lines)
        block = self.view.linear_viewer.objects[self.main.addr]
        assert len(block.insn_addrs) == 9
        # the same object comes back from the cache while the block is unchanged
        self.view.linear_viewer.refresh()
        assert self.view.linear_viewer.objects[self.main.addr] is block

    def test_scrolling_and_data(self):
        self.presenter.display_linear_viewer()
        linear = self.view.linear_viewer
        linear.navigate_to_addr(0x400915)
        texts = [line.text for _node, line in linear.lines()]
        assert any("Username: " in t for t in texts)
        assert any(addr == 0x400915 for addr, _ in linear.visible_memory_data)
        offset = linear.offset
        linear.scroll(5)
        assert (linear.offset, linear.start_line) != (offset, 0)
        linear.scroll(-5)
        # back up at least as far as where it started (the walk counts lines from the floor object, as in Qt)
        assert linear.offset <= offset

    def test_cfb_update(self):
        self.presenter.display_linear_viewer()
        self.presenter.display_function(self.main)
        assert len(self.view.linear_viewer.objects[self.main.addr].insn_addrs) == 9
        self.presenter.infodock.select_instruction(self.main.addr + 4)
        assert self.presenter.infodock.selected_insns == {self.main.addr + 4}
        self.presenter.undefine_code()
        self.workspace.job_manager.join_all_jobs()
        self.presenter.display_function(self.main)
        assert len(self.view.linear_viewer.objects[self.main.addr].insn_addrs) == 2


class TestFind(FauxwareDisasmCase):
    def test_find_in_graph(self):
        self.presenter.display_function(self.main)
        self.presenter.show_find_bar()
        bar = self.view.find_bar
        bar.set_query("call")
        calls = [m for m in self.presenter.find_matches if "call" in m[1]]
        assert calls and len(calls) == len(self.presenter.find_matches)
        assert self.presenter.find_index == 0
        assert bar.status == f"1 of {len(calls)}"
        first = self.presenter.find_matches[0][0]
        assert first in self.presenter.infodock.selected_insns
        self.presenter.find_next()
        assert self.presenter.find_index == 1
        self.presenter.find_previous()
        self.presenter.find_previous()
        assert self.presenter.find_index == len(calls) - 1
        current = self.presenter.find_matches[self.presenter.find_index][0]
        bar.close_bar()
        assert self.presenter.find_matches == []
        # only the current match stays selected
        assert self.presenter.infodock.selected_insns == {current}

    def test_find_bar_open_follows_the_bar(self):
        self.presenter.display_function(self.main)
        assert not self.presenter.find_bar_open()
        self.presenter.show_find_bar()
        assert self.presenter.find_bar_open()
        self.view.find_bar.close_bar()
        assert not self.presenter.find_bar_open()

    def test_find_bytes_and_bad_regex(self):
        self.presenter.display_function(self.main)
        self.presenter.show_find_bar()
        bar = self.view.find_bar
        bar.set_mode(DisasmPresenter.FIND_MODE_BYTES)
        bar.set_query("55 48 89 e5")
        assert [m[0] for m in self.presenter.find_matches] == [self.main.addr]
        bar.set_mode(DisasmPresenter.FIND_MODE_TEXT)
        bar.set_use_regex(True)
        bar.set_query("([")
        assert bar.error
        assert self.presenter.find_matches == []


class TestMenusKeysCommands(FauxwareDisasmCase):
    def test_instruction_menu(self):
        self.presenter.display_function(self.main)
        menu = self.presenter.insn_context_menu(self.main.addr)
        texts = [e.text for _, e in walk_entries(menu)]
        for expected in ["Toggle selection", "XRefs...", "Comment", "Toggle bookmark", "Patch...", "None available"]:
            assert expected in texts, expected

    def test_label_and_unknown_menus(self):
        label = [e.text for _, e in walk_entries(self.presenter.label_context_menu(self.main.addr))]
        assert "XRefs..." in label and "Resume CFG recovery from here" in label
        unknown = [e.text for _, e in walk_entries(self.presenter.unknown_context_menu(0x400000))]
        assert unknown[:2] == ["Resume CFG recovery from here", "Resume full CFG recovery"]

    def test_menu_entries_run_on_the_presenter(self):
        self.presenter.display_function(self.main)
        menu = self.presenter.insn_context_menu(self.insns[2])
        entry = next(e for _, e in walk_entries(menu) if e.text == "Toggle bookmark")
        entry.trigger()
        assert self.instance.annotations.has_bookmark(self.insns[2])

    def test_xrefs_needs_a_selection(self):
        messages = []

        class Recording(HeadlessServices):
            def message(self, kind, title, text, *args, **kwargs):  # pylint: disable=unused-argument
                messages.append(title)

        set_services(Recording())
        self.presenter.display_function(self.main)
        self.presenter.xrefs_for_selection()
        assert messages == ["Invalid selection for XRefs"]
        self.presenter.infodock.select_label(self.main.addr)
        assert self.presenter.xrefs_target() == {"addr": self.main.addr, "dst_addr": self.main.addr}

    def test_keymap_has_the_qt_keys(self):
        chords = {b.chord: b.action for b in disassembly_keymap()}
        for chord, action in [
            ("G", "popup_jumpto_dialog"),
            ("Esc", "jump_back"),
            ("A", "toggle_smart_highlighting"),
            ("Tab", "decompile_current_function"),
            (";", "begin_inline_comment"),
            ("Space", "toggle_disasm_view"),
            ("C", "define_code"),
            ("U", "undefine_code"),
            ("N", "popup_rename_label_dialog"),
            ("X", "xrefs"),
            ("Ctrl+F", "show_find_bar"),
            ("F3", "find_next"),
        ]:
            assert chords.get(chord) == action, chord
        for _chord, action in chords.items():
            assert hasattr(self.presenter, action) or action in (
                "xrefs",
                "more_detail",
                "less_detail",
                "reset_detail",
                "context_menu",
                "activate",
            )

    def test_commands_run_on_the_focused_presenter(self):
        register_disasm_commands(self.workspace)
        commands = self.workspace.command_manager.get_commands()
        names = [c.name for c in commands if c.name.startswith("disassembly_view_")]
        assert len(names) == len(DISASM_COMMANDS) == 21
        self.workspace.view_manager.add_view(self.view)
        self.workspace.view_manager.handle_focus_changed(self.view)
        assert self.workspace.view_manager.most_recently_focused_view is self.view
        command = next(c for c in commands if c.name == "disassembly_view_toggle_show_address")
        assert command.is_visible
        command.run()
        assert not self.presenter.show_address

    def test_marks(self):
        self.presenter.display_function(self.main)
        self.instance.breakpoint_mgr.toggle_exec_breakpoint(self.insns[1])
        marks = self.presenter.marks_at(self.insns[1])
        assert [m.text for m in marks] == ["break"]
        marks[0].action()
        assert not self.presenter.marks_at(self.insns[1])

    def test_nodes_know_their_labels(self):
        doc, _ = self.presenter.graph_doc(FunctionGraph(self.main))
        labels = [n for b in doc.blocks.values() for n in b.nodes if isinstance(n, LabelNode)]
        assert all(n.text.endswith(":") for n in labels)


class InductionExpr:
    """Stands in for the expression class the induction variable hack matches by name."""

    def __init__(self, stride: int, init: int) -> None:
        self.stride = stride
        self.init = init


class Add:
    def __init__(self, *operands: Any) -> None:
        self.operands = operands


class FakeInductionVariables:
    """Every variable is ``i*4 + 8`` plus 2."""

    def __init__(self) -> None:
        self.variables = self

    def get(self, ident: Any, default: Any = None) -> Any:  # pylint:disable=unused-argument
        return SimpleNamespace(expr=Add(InductionExpr(4, 8), SimpleNamespace(value=2)))


class TestOperandText(FauxwareDisasmCase):
    def test_induction_variable_offset_is_computed(self):
        analyses: Any = self.project.analyses
        analyses.VariableRecoveryFast(self.main)
        self.presenter.display_function(self.main)
        self.presenter.infodock.induction_variable_analysis = FakeInductionVariables()
        doc, _ = self.presenter.graph_doc(FunctionGraph(self.main))
        labels = [
            op.variable_label
            for b in doc.blocks.values()
            for n in b.nodes
            if isinstance(n, InsnNode)
            for op in n.operands
            if op.variable is not None and op.variable_label
        ]
        assert labels, "no memory operand of main has a variable"
        assert all("i*4+10" in label for label in labels), labels
        assert not any("r.expr" in label for label in labels), labels


if __name__ == "__main__":
    unittest.main()
