"""
The pseudocode presenter on fauxware, without a window: the render model, the position-map helpers, rename, retype
and comment round trips seen in codegen.text, the context menu, keys and commands, find, flavors, jumps, the options
sheet, the pattern highlight, and the fold scopes (checked against the Qt editor's pyqodeng folding).
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use

from __future__ import annotations

import os
import re
import unittest
from typing import Any
from unittest.mock import patch

import angr
from angr.analyses.decompiler.structured_codegen import (
    ConstantNode,
    FunctionCallNode,
    FunctionNode,
    UnaryOpNode,
    VariableNode,
)
from angr.knowledge_plugins.patterns import StoredPattern
from angr.sim_type import SimTypeInt, SimTypeLongLong

from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.headless_workspace import HeadlessWorkspace
from angrmanagement.logic.ui_services import HeadlessServices
from angrmanagement.present import code as code_module
from angrmanagement.present.code import (
    CODE_COMMANDS,
    CodePresenter,
    HeadlessCodeView,
    closest_node_pos,
    node_at_position,
    parse_type_text,
    pseudocode_keymap,
    register_code_commands,
    related_text_chunks,
    rename_node_directly,
    stmt_node_at_position,
)
from angrmanagement.present.code_highlight import highlight_runs, kind_style, resolve_runs
from angrmanagement.present.code_patterns import PatternLibraryModel
from angrmanagement.present.folding import FoldMap
from angrmanagement.present.menus import MenuEntry, MenuSeparator

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
AFTER909 = os.path.join(test_location, "x86_64", "1after909")


def set_services(services: Any) -> None:
    GlobalInfo.ui_services = services  # pyright: ignore[reportAttributeAccessIssue]


class PromptServices(HeadlessServices):
    """Headless services that answer every prompt with the next of the given texts."""

    def __init__(self, *answers: str | None) -> None:
        super().__init__()
        self.answers = list(answers)
        self.prompts: list[tuple[str, str]] = []
        self.messages: list[str] = []

    def prompt_text(self, title: str, label: str, default: str = "") -> str | None:
        self.prompts.append((title, default))
        return self.answers.pop(0) if self.answers else None

    def message(self, level, title: str, text: str) -> None:
        self.messages.append(text)


def load_fauxware(path: str = FAUXWARE) -> tuple[angr.Project, Any, Any]:
    project = angr.Project(path, auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True, data_references=True, cross_references=True)
    analyses: Any = project.analyses
    analyses.CompleteCallingConventions(recover_variables=True)
    cfb = analyses.CFB(kb=project.kb)
    return project, cfg, cfb


class FauxwareCodeCase(unittest.TestCase):
    """A headless workspace with fauxware, and a pseudocode view that draws nothing showing main."""

    def setUp(self):
        self.project, self.cfg, self.cfb = load_fauxware()
        self.saved_services = GlobalInfo._ui_services
        set_services(HeadlessServices())
        self.workspace, self.view = self.open_view(self.project, self.cfg, self.cfb)
        self.presenter: Any = self.view.presenter
        self.main = self.project.kb.functions["main"]
        self.show(self.view, self.main)

    def open_view(self, project, cfg, cfb) -> tuple[Any, Any]:
        workspace: Any = HeadlessWorkspace(auto_analyze=False)
        instance = workspace.main_instance
        instance.project.am_obj = project
        instance.project.am_event()
        instance.cfg.am_obj = cfg.model
        instance.cfg.am_event()
        instance.cfb.am_obj = cfb
        instance.cfb.am_event()
        view = HeadlessCodeView(workspace, instance)
        workspace.view_manager.add_view(view)
        return workspace, view

    @staticmethod
    def show(view, func) -> None:
        view.function.am_obj = func
        view.function.am_event()
        view.workspace.job_manager.join_all_jobs()

    def tearDown(self):
        self.view.close()
        set_services(self.saved_services)
        self.workspace.job_manager.quit()

    @property
    def text(self) -> str:
        return self.presenter.codegen.text

    def element(self, text: str, kind: type, nth: int = 0):
        """The ``nth`` position-map element of a node of ``kind`` that renders as ``text``."""
        found = [
            elem
            for _pos, elem in sorted(self.presenter.codegen.map_pos_to_node.items())
            if isinstance(elem.obj, kind) and self.text[elem.start : elem.start + elem.length] == text
        ]
        return found[nth]

    def line_of(self, needle: str) -> int:
        return next(idx for idx, line in enumerate(self.text.split("\n")) if needle in line)


class TestRender(FauxwareCodeCase):
    def test_decompiles_main_and_draws_every_line(self):
        assert not self.presenter.codegen.am_none
        assert self.text.startswith("int main(")
        doc = self.presenter.doc
        assert doc is not None
        assert [line.text for line in doc.lines] == self.text.split("\n")
        # each line starts where the text says
        for row, start in enumerate(doc.line_starts):
            assert self.text[start:].startswith(doc.lines[row].text)
            assert doc.row_column(start) == (row, 0)
        assert doc.position(1, 0) == len(self.text.split("\n")[0]) + 1

    def test_spans_carry_the_highlighter_styles_and_the_nodes(self):
        doc = self.presenter.doc

        def span_of(row: int, text: str):
            return next(span for span in doc.lines[row].spans if span.text == text)

        row = self.line_of('puts("Username: ")')
        puts = span_of(row, "puts")
        assert isinstance(puts.node, FunctionCallNode)
        assert puts.style == kind_style("library_function")
        assert span_of(row, '"Username: "').style == kind_style("quotation")
        row = self.line_of("authenticate(")
        assert span_of(row, "authenticate").style == kind_style("function")
        assert span_of(self.line_of("return accepted"), "return").style == kind_style("keyword")
        assert span_of(self.line_of("do not return"), "/* do not return */").style == kind_style("comment")
        assert span_of(0, "int").style == kind_style("type")
        assert isinstance(span_of(0, "main").node, FunctionNode)

    def test_runs_are_the_writes_laid_over_as_qt_lays_them(self):
        # a later write wins, one starting before the line is dropped, one past its end is cut
        assert resolve_runs([(0, 4, "keyword"), (2, 1, "comment"), (-1, 3, "type"), (3, 9, "label")], 5) == [
            (0, 2, "keyword"),
            (2, 1, "comment"),
            (3, 2, "label"),
        ]
        runs, in_comment = highlight_runs("a /* b", 0, None, "pseudocode", False)
        assert runs == [(2, 4, "comment")] and in_comment
        runs, in_comment = highlight_runs("c */ if", 0, None, "pseudocode", True)
        assert runs == [(0, 4, "comment"), (5, 2, "keyword")] and not in_comment
        # the flavor picks the keywords
        assert highlight_runs("fn x", 0, None, "rust", False)[0] == [(0, 2, "keyword")]
        assert not highlight_runs("fn x", 0, None, "pseudocode", False)[0]


class TestPositions(FauxwareCodeCase):
    def test_node_at_position_looks_one_back(self):
        elem = self.element("v5", VariableNode)
        codegen = self.presenter.codegen
        assert node_at_position(codegen, elem.start) is elem.obj
        # a cursor right after the name is still on it
        assert node_at_position(codegen, elem.start + elem.length) is elem.obj

    def test_related_chunks_are_every_mention(self):
        elem = self.element("v5", VariableNode)
        chunks = related_text_chunks(self.presenter.codegen, elem.obj)
        assert chunks
        assert all(self.text[start:end] == "v5" for start, end in chunks)
        assert len(chunks) == len(re.findall(r"\bv5\b", self.text))

    def test_statement_node_and_closest_position(self):
        codegen = self.presenter.codegen
        row = self.line_of('puts("Username: ")')
        start = self.presenter.doc.line_starts[row]
        # the indentation has no node; the statement of the line is found to the right
        node = stmt_node_at_position(codegen, start)
        assert node is not None and "ins_addr" in node.tags
        assert closest_node_pos(codegen, node.tags["ins_addr"]) is not None

    def test_cursor_highlights_the_mentions_and_moves_the_address(self):
        elem = self.element("v5", VariableNode)
        self.view.set_cursor_position(elem.start)
        assert self.presenter.current_node.am_obj is elem.obj
        assert len(self.presenter.chunks) == len(re.findall(r"\bv5\b", self.text))
        assert self.presenter.addr.am_obj == self.presenter.src_to_inst(elem.start)


class TestEdits(FauxwareCodeCase):
    def test_rename_a_local_variable(self):
        elem = self.element("v5", VariableNode)
        set_services(PromptServices("username"))
        self.view.set_cursor_position(elem.start)
        self.presenter.select_node_at_cursor()
        self.presenter.rename_node()
        assert "username" in self.text and not re.search(r"\bv5\b", self.text)
        assert elem.obj.unified_variable.name == "username"
        # through the edit layer: the variable is no longer an automatic name
        assert elem.obj.unified_variable.renamed

    def test_rename_asks_with_the_current_name(self):
        elem = self.element("v5", VariableNode)
        services = PromptServices(None)
        set_services(services)
        self.presenter.rename_node(elem.obj)
        assert services.prompts == [("Rename", "v5")]
        assert "v5" in self.text

    def test_an_invalid_name_is_refused(self):
        elem = self.element("v5", VariableNode)
        services = PromptServices("two words")
        set_services(services)
        self.presenter.rename_node(elem.obj)
        assert services.messages and "v5" in self.text

    def test_rename_the_function_and_a_callee(self):
        self.presenter.apply_rename(self.element("main", FunctionNode).obj, "entry")
        self.presenter.apply_rename(self.element("authenticate", FunctionCallNode).obj, "check_password")
        self.presenter.codegen.am_event()
        assert self.text.startswith("int entry(")
        assert "check_password(&v5, v3)" in self.text
        func: Any = self.project.kb.functions.function(addr=self.main.addr)
        assert func.name == "entry"

    def test_plugins_hear_the_callee_the_argument_index_and_retypes(self):
        """
        Through the edit layer the plugins are told what the MCP tools tell them: a renamed call names the callee
        (the rename dialog named the function shown), a renamed argument its own index (the dialog said 0), and a
        retype is announced (the dialog announced none).
        """
        plugins = self.workspace.plugins
        authenticate = self.project.kb.functions["authenticate"]
        with (
            patch.object(plugins, "handle_function_renamed") as function_renamed,
            patch.object(plugins, "handle_func_arg_renamed") as arg_renamed,
            patch.object(plugins, "handle_stack_var_retyped") as stack_var_retyped,
        ):
            assert self.presenter.apply_rename(self.element("authenticate", FunctionCallNode).obj, "check_password")
            function_renamed.assert_called_once_with(authenticate, "authenticate", "check_password")
            assert self.presenter.apply_rename(self.element("a1", VariableNode).obj, "argv")
            arg_renamed.assert_called_once()
            func, index, old_name, new_name = arg_renamed.call_args.args
            assert (func.addr, index, old_name, new_name) == (self.main.addr, 1, "a1", "argv")
            v5 = self.element("v5", VariableNode).obj
            self.presenter.apply_retype(v5, SimTypeLongLong())
            self.workspace.job_manager.join_all_jobs()
            stack_var_retyped.assert_called_once()
            func, offset, _old_type, new_type = stack_var_retyped.call_args.args
            assert (func.addr, offset, new_type.c_repr()) == (self.main.addr, v5.variable.offset, "long long")

    def test_a_retyped_argument_is_announced_as_a_new_prototype(self):
        """
        Retyping an argument changes the prototype, as the Qt editor always did, so the plugins hear
        handle_function_retyped with the new prototype and not handle_func_arg_retyped (which the MCP tools send).
        """
        plugins = self.workspace.plugins
        with (
            patch.object(plugins, "handle_function_retyped") as function_retyped,
            patch.object(plugins, "handle_func_arg_retyped") as arg_retyped,
        ):
            self.presenter.apply_retype(self.element("a0", VariableNode).obj, SimTypeLongLong())
            self.workspace.job_manager.join_all_jobs()
            arg_retyped.assert_not_called()
            function_retyped.assert_called_once()
            func, _old_proto, new_proto = function_retyped.call_args.args
            assert func.addr == self.main.addr
            assert new_proto.args[0].c_repr() == "long long"

    def compare_renames(self, path: str, func_name: str, renames) -> None:
        """
        Rename through the presenter (the edit layer) in one project of ``path`` and directly, as the rename dialog
        did before, in another; the texts must be the same after each rename.
        """
        views = []
        try:
            for _ in range(2):
                project, cfg, cfb = load_fauxware(path)
                workspace, view = self.open_view(project, cfg, cfb)
                views.append((workspace, view))
                self.show(view, project.kb.functions[func_name])
            ours: Any = views[0][1].presenter
            theirs: Any = views[1][1].presenter
            assert ours.codegen.text == theirs.codegen.text
            spies = [
                patch.object(code_module, name, wraps=getattr(code_module, name))
                for name in ("core_rename_variable", "core_rename_function", "rename_node_directly")
            ]
            rename_variable, rename_function, directly = (spy.start() for spy in spies)
            for spy in spies:
                self.addCleanup(spy.stop)
            for text, kind, new in renames:

                def node_of(presenter, text=text, kind=kind):
                    codegen = presenter.codegen
                    return next(
                        elem.obj
                        for _pos, elem in sorted(codegen.map_pos_to_node.items())
                        if isinstance(elem.obj, kind) and codegen.text[elem.start : elem.start + elem.length] == text
                    )

                assert ours.apply_rename(node_of(ours), new)
                ours.codegen.am_event()
                workspace, view = views[1]
                rename_node_directly(
                    workspace, view.instance, theirs.codegen.am_obj, node_of(theirs), new, theirs.function
                )
                theirs.codegen.am_event()
                assert new in ours.codegen.text, text
                assert ours.codegen.text == theirs.codegen.text, text
            # every rename went through the edit layer
            assert rename_variable.call_count + rename_function.call_count == len(renames)
            assert directly.call_count == 0
        finally:
            for workspace, view in views:
                view.close()
                workspace.job_manager.quit()

    def test_edits_give_the_same_text_as_the_dialog_did(self):
        self.compare_renames(
            FAUXWARE,
            "main",
            [
                ("v5", VariableNode, "username"),
                ("a0", VariableNode, "argc"),
                ("main", FunctionNode, "entry"),
                ("authenticate", FunctionCallNode, "check_password"),
            ],
        )

    def test_edits_give_the_same_text_for_a_global(self):
        self.compare_renames(AFTER909, "doit", [("stdout", VariableNode, "std_notout")])

    def test_retype_a_local_variable(self):
        elem = self.element("v5", VariableNode)
        variable = elem.obj.variable
        set_services(PromptServices("long long"))
        self.presenter.retype_node(elem.obj)
        self.workspace.job_manager.join_all_jobs()
        vm = self.project.kb.dec_variables[self.main.addr]
        assert vm.get_variable_type(variable).c_repr() == "long long"
        assert re.search(r"long long v5;", self.text)

    def test_retype_text_parses_declarations_and_types(self):
        valid, _reason, type_ = parse_type_text("unsigned int x")
        assert valid and type_ is not None and type_.c_repr() == "unsigned int"
        assert parse_type_text("char *")[0]
        valid, reason, _ = parse_type_text("struct nosuchstruct")
        assert not valid and "nosuchstruct" in reason

    def test_statement_comment_goes_to_the_kb_and_shows(self):
        row = self.line_of('puts("Password: ")')
        self.view.set_cursor_position(self.presenter.doc.line_starts[row] + 4)
        set_services(PromptServices("ask for the password"))
        self.presenter.comment()
        addr = self.presenter.closest_insaddr(None)
        assert self.project.kb.comments[addr] == "ask for the password"
        assert "ask for the password" in self.text.split("\n")[row]

    def test_expression_comment(self):
        elem = self.element("authenticate", FunctionCallNode)
        self.view.set_cursor_position(elem.start)
        set_services(PromptServices("returns 1 on success"))
        self.presenter.comment_expr()
        assert "returns 1 on success" in self.presenter.codegen.expr_comments.values()
        assert "returns 1 on success" in self.text

    def test_constant_formats(self):
        elem = self.element("8", ConstantNode)
        self.presenter.hex_constant(elem.obj)
        assert "0x8" in self.text
        self.presenter.hex_constant(elem.obj)
        assert "0x8" not in self.text


class TestMenusAndKeys(FauxwareCodeCase):
    # what the Qt context menu shows for each kind of node of main
    COMMON = [
        "Comment...|;",
        "Create pattern from selection...|",
        "---",
        "Copy|Ctrl+C",
        "Select all|Ctrl+A",
        "---",
        "AI: Refine All|",
        "AI: Suggest Variable Names|",
        "AI: Suggest Function Name|",
        "AI: Suggest Variable Types|",
    ]
    EXPR = ["Create a ternary expression|", "Swap operands|", "Collapse expression|", "Expand expression|"]

    @staticmethod
    def entries(menu) -> list[str]:
        out = []
        for item in menu.items():
            if isinstance(item, MenuSeparator):
                out.append("---")
            elif isinstance(item, MenuEntry):
                out.append(f"{item.caption}|{item.shortcut or ''}")
        return out

    def test_menus_are_the_qt_menus(self):
        cases = [
            (("int", SimTypeInt), self.COMMON),
            (("main", FunctionNode), ["Rename...|N", "Xrefs...|X", "Specify a new type|Y", *self.COMMON]),
            (
                ("a0", VariableNode),
                [
                    "Rename...|N",
                    "Specify a new type|Y",
                    "Toggle &struct/array|",
                    "Expression -> ARM THUMB assembly...|",
                    "Xrefs...|X",
                    *self.EXPR,
                    *self.COMMON,
                ],
            ),
            (
                ("0", ConstantNode),
                [
                    "Toggle hex|H",
                    "Toggle negative|_",
                    "Toggle char|R",
                    "Toggle float|",
                    "Toggle double|",
                    *self.EXPR,
                    *self.COMMON,
                ],
            ),
            (("puts", FunctionCallNode), ["Rename...|N", "Xrefs...|X", *self.EXPR, *self.COMMON]),
            (("&", UnaryOpNode), [*self.EXPR, *self.COMMON]),
        ]
        for (text, kind), expected in cases:
            node = self.element(text, kind).obj
            menu = self.presenter.context_menu(node=node)
            assert self.entries(menu) == expected, text

    def test_a_function_node_the_kb_does_not_know_still_gets_its_menu(self):
        # the Qt menu raised KeyError here before the presenter built it; now the plugins' function entries are left out
        node = self.element("main", FunctionNode).obj
        plugins = self.workspace.plugins
        with (
            patch.object(node, "name", "not_a_function_of_the_kb"),
            patch.object(plugins, "build_context_menu_functions") as function_entries,
        ):
            menu = self.presenter.context_menu(node=node)
        function_entries.assert_not_called()
        assert self.entries(menu) == ["Rename...|N", "Xrefs...|X", "Specify a new type|Y", *self.COMMON]

    def test_clear_highlights_entry_while_there_is_a_highlight(self):
        self.presenter.highlight_pattern(self.main.addr, [frozenset({self.main.addr})])
        menu = self.presenter.context_menu(node=None)
        assert self.entries(menu)[-2:] == ["---", "Clear pattern highlights|"]

    def test_menu_entries_run_on_the_node(self):
        node = self.element("8", ConstantNode).obj
        menu = self.presenter.context_menu(node=node)
        entry = next(item for item in menu.items() if isinstance(item, MenuEntry) and item.text == "Toggle hex")
        entry.trigger()
        assert "0x8" in self.text

    def test_every_key_runs_an_action(self):
        keymap = pseudocode_keymap()
        assert keymap.scope == "pseudocode"
        for binding in keymap:
            if binding.action != "context_menu":
                assert callable(getattr(self.presenter, binding.action)), binding.action
        chords = {binding.chord for binding in keymap}
        # CodeView.keyPressEvent, QCCodeEdit's menu shortcuts and keyPressEvent, and the find shortcuts
        for chord in ["Tab", "G", "Esc", "Space", "N", "X", "Y", "H", "_", "R", ";", "/", "?", ":", "Ctrl+F", "F3"]:
            assert chord in chords, chord

    def test_commands(self):
        register_code_commands(self.workspace)
        names = {cmd.name for cmd in self.workspace.command_manager.get_commands()}
        for _caption, method in CODE_COMMANDS:
            assert f"code_view_{method}" in names


class TestNavigation(FauxwareCodeCase):
    def test_double_click_on_a_call_decompiles_the_callee(self):
        elem = self.element("authenticate", FunctionCallNode)
        with patch.object(self.workspace, "decompile_function") as decompile_function:
            self.view.set_cursor_position(elem.start)
            self.presenter.activate()
        decompile_function.assert_called_once()
        assert decompile_function.call_args.args[0] is elem.obj.callee_func
        assert self.presenter.jump_history.current == elem.obj.callee_func.addr

    def test_jumping_into_another_function_shows_it_and_back(self):
        auth = self.project.kb.functions["authenticate"]
        self.presenter.jump_to(auth.addr)
        self.workspace.job_manager.join_all_jobs()
        assert self.presenter.function.am_obj is auth
        assert "unsigned int authenticate(char *a0, char *a1)" in self.text
        self.presenter.jump_back()
        self.workspace.job_manager.join_all_jobs()
        assert self.presenter.function.am_obj is self.main

    def test_tab_goes_to_the_cursor_address_in_the_disassembly(self):
        with patch.object(self.workspace, "jump_to") as jump_to:
            self.presenter.addr.am_obj = 0
            self.presenter.go_to_disassembly()
        jump_to.assert_called_once_with(self.main.addr)

    def test_flavors(self):
        assert self.presenter.flavor == "pseudocode"
        assert "pseudocode" in self.presenter.available_flavors
        before = self.text
        self.presenter.next_flavor()
        # fauxware has one flavor: Space shows it again
        assert self.presenter.flavor == "pseudocode" and self.text == before
        menu = self.presenter.flavor_menu()
        assert [entry.text for entry in menu.items()] == self.presenter.available_flavors


class TestFind(FauxwareCodeCase):
    def test_find_counts_and_steps(self):
        self.presenter.show_find_bar()
        self.view.find_bar.set_query("read")
        matches = self.presenter.find_matches
        assert len(matches) == self.text.count("read")
        assert self.view.selection_range() == matches[0]
        self.presenter.find_next()
        assert self.view.selection_range() == matches[1]
        self.presenter.find_previous()
        self.presenter.find_previous()
        assert self.view.selection_range() == matches[-1]
        assert self.view.find_bar.status == f"{len(matches)} of {len(matches)}"
        self.view.find_bar.close_bar()
        assert not self.presenter.find_matches

    def test_find_starts_from_the_selected_word(self):
        elem = self.element("v5", VariableNode)
        self.view.select_range(elem.start, elem.start + elem.length)
        self.presenter.show_find_bar()
        assert self.view.find_bar.query == "v5"


class TestOptionsAndPatterns(FauxwareCodeCase):
    def test_options_sheet(self):
        sheet = self.presenter.options
        assert sheet.passes and sheet.selected_passes
        option = sheet.options[0]
        assert dict(sheet.option_and_values)[option] == option.default_value
        sheet.dirty = False
        first_pass = sheet.passes[0]
        sheet.set_value(first_pass, not sheet.values[first_pass])
        assert sheet.dirty
        assert (first_pass in sheet.selected_passes) == sheet.values[first_pass]
        # back to the preset's values
        default = sheet.values[first_pass]
        sheet.reload(force=True)
        assert sheet.values[first_pass] != default
        groups = [name for name, _items in sheet.groups()]
        assert groups[-2:] == ["Optimization Passes", "Peephole Optimizations"]

    def test_pattern_highlight_bands_the_lines(self):
        row = self.line_of('puts("Username: ")')
        node = stmt_node_at_position(self.presenter.codegen, self.presenter.doc.line_starts[row] + 4)
        self.presenter.highlight_pattern(self.main.addr, [frozenset({node.tags["ins_addr"]})])
        assert row in self.presenter.pattern_highlight_rows()
        assert self.presenter.has_pattern_highlight
        assert self.presenter.clear_pattern_highlight()
        assert not self.presenter.pattern_highlight_rows()

    def test_patterns_pane_model(self):
        doc = self.presenter.doc
        first = self.line_of("read(0, &v5, 8);")
        last = self.line_of("read(0, &v2, 1);")
        start = doc.line_starts[first]
        end = doc.line_starts[last] + doc.lines[last].width
        pattern = self.presenter.make_pattern(start, end, "two_reads")
        assert pattern is not None
        kb = self.project.kb
        kb.patterns.store(StoredPattern(pattern, enabled=False, origin_func=self.main.addr))
        statuses: list[str] = []
        model = PatternLibraryModel(self.presenter, on_status=statuses.append)
        assert model.row_count == 1
        name = pattern.name
        assert [model.cell(0, col).text for col in range(5)] == [name, "off", "", "0", "0"]
        assert model.cell(0, 5).text == "two_reads"
        # a click on Enabled only marks the pattern; Apply turns it on and decompiles again
        assert model.set_checked(0, model.ENABLED, True)
        assert model.cell(0, model.ENABLED).text == "on (unapplied)" and not kb.patterns.get(name).enabled
        assert model.apply_pending()
        self.workspace.job_manager.join_all_jobs()
        assert kb.patterns.get(name).enabled
        assert "two_reads(" in self.text
        model.reload()
        assert int(model.cell(0, 4).text) >= 1
        # the highlight box bands the call in the pseudocode
        assert model.set_checked(0, model.HIGHLIGHT, True)
        assert self.presenter.is_pattern_highlighted(name)
        assert self.line_of("two_reads(") in self.presenter.pattern_highlight_rows()
        menu = model.context_menu([0])
        assert menu is not None
        assert [entry.text for entry in menu.items() if isinstance(entry, MenuEntry)] == [
            "Highlight patterns in pseudocode",
            "Highlight patterns in disassembly",
            "Edit pattern...",
            "Apply Patterns & Redecompile",
            "Clear highlights",
        ]

    def test_the_options_sheet_is_made_when_first_asked_for(self):
        with patch.object(
            code_module, "DecompilationOptionsSheet", wraps=code_module.DecompilationOptionsSheet
        ) as made:
            presenter = CodePresenter(self.workspace, self.workspace.main_instance)
            made.assert_not_called()
            sheet = presenter.options
            assert presenter.options is sheet
        made.assert_called_once()

    def test_hover_text_of_a_call(self):
        elem = self.element("authenticate", FunctionCallNode)
        text = CodePresenter.hover_text(elem.obj)
        assert text is not None and "authenticate(" in text and "@ <rdi>" in text
        assert CodePresenter.hover_text(self.element("v5", VariableNode).obj) is None


class TestWorkspaceUses(FauxwareCodeCase):
    """The workspace actions that read the pseudocode view's function as ``code_view._function``."""

    def test_discover_patterns_reads_the_function_shown(self):
        assert self.view._function is self.presenter.function
        with patch.object(self.workspace, "_get_or_create_view", return_value=None) as get_view:
            assert self.workspace.discover_patterns() is None
        get_view.assert_called_once_with("pattern")

    def test_ai_refine_runs_on_the_function_shown(self):
        with (
            patch.object(self.project, "_llm_client", object()),
            patch("angrmanagement.logic.workspace.LLMRefineJob") as job,
            patch.object(self.workspace.job_manager, "add_job") as add_job,
        ):
            self.workspace.llm_refine_all()
        job.assert_called_once()
        assert job.call_args.args[1] is self.main
        add_job.assert_called_once_with(job.return_value)


NESTED = """int f()
{
    if (a) {
        b();
    } else {
        c();
    }


    while (1)
    {
        d();
    }
}
"""


def pyqodeng_scopes(text: str) -> tuple[list[int], dict[int, int]]:
    """The fold levels and scopes the Qt pseudocode editor gives ``text``: pyqodeng's CharBasedFoldDetector."""
    # pylint: disable=import-outside-toplevel
    from pyqodeng.core.api import CharBasedFoldDetector, CodeEdit, FoldScope, SyntaxHighlighter, TextBlockHelper
    from PySide6.QtWidgets import QApplication

    _app = QApplication.instance() or QApplication([])

    class Highlighter(SyntaxHighlighter):
        def highlight_block(self, text, block):
            pass

    editor = CodeEdit()
    highlighter = Highlighter(editor.document())
    editor.modes.append(highlighter)
    highlighter.fold_detector = CharBasedFoldDetector()
    editor.setPlainText(text, "text/x-c", "utf-8")
    highlighter.rehighlight()
    levels: list[int] = []
    scopes: dict[int, int] = {}
    block = editor.document().firstBlock()
    while block.isValid():
        levels.append(TextBlockHelper.get_fold_lvl(block))
        if TextBlockHelper.is_fold_trigger(block):
            first, last = FoldScope(block).get_range()
            if last > first:
                scopes[first] = last
        block = block.next()
    editor.close()
    return levels, scopes


class TestFolding(FauxwareCodeCase):
    def test_scopes_of_nested_blocks(self):
        folds = FoldMap(NESTED.split("\n"))
        # the signature folds the body and the while its block; "} else {" opens a level without closing one in
        # pyqodeng's detector, so the if folds to the end of the function and the else one line further, as in Qt
        assert folds.scopes == {0: 13, 2: 13, 4: 6, 9: 12}
        assert folds.scope_of(3) == 2 and folds.scope_of(11) == 9 and folds.scope_of(7) == 2
        folds.fold(2)
        folds.fold(0)
        assert folds.visible_rows() == [0, 14]
        # unfolding a scope unfolds the scopes inside it, as FoldScope.unfold does
        folds.unfold(0)
        assert folds.folded == set() and len(folds.visible_rows()) == 15
        folds.fold(9)
        assert folds.is_hidden(11) and folds.reveal(11) and not folds.is_hidden(11)
        folds.fold_all()
        assert folds.visible_rows() == [0, 14]
        folds.unfold_all()
        assert folds.folded == set()

    def test_the_scopes_are_the_qt_editors(self):
        # every non-trivial function of fauxware, as the Qt pseudocode editor's folding panel folds it
        texts = [NESTED, self.text]
        for func in self.project.kb.functions.values():
            if func.is_plt or func.is_simprocedure or func.is_alignment:
                continue
            dec = self.project.analyses.Decompiler(func, cfg=self.cfg.model)
            if dec.codegen is not None and dec.codegen.text:
                texts.append(dec.codegen.text)
        assert len(texts) > 5
        for text in texts:
            lines = text.split("\n")
            levels, scopes = pyqodeng_scopes(text)
            folds = FoldMap(lines)
            assert folds.levels == levels[: len(lines)], text
            assert folds.scopes == scopes, text

    def test_main_folds_under_its_signature(self):
        doc = self.presenter.doc
        folds = self.presenter.folds
        assert doc is not None and folds is not None
        # the one fold trigger of main is its signature, where the Qt editor draws its fold arrow
        assert folds.scopes == {0: len(doc.lines) - 2}
        row = next(i for i, line in enumerate(doc.lines) if "puts(" in line.text)
        self.view.cursor = doc.position(row, 4)
        self.presenter.toggle_fold()
        assert folds.folded == {0}
        self.presenter.toggle_fold()
        assert folds.folded == set()
        self.presenter.fold_all()
        assert folds.folded == {0}
        self.presenter.unfold_all()
        assert folds.folded == set()
        # new text unfolds everything
        self.presenter.fold_all()
        self.presenter.build_doc()
        assert self.presenter.folds is not folds and self.presenter.folds.folded == set()

    def test_fold_keys(self):
        def actions(tier: int) -> dict[str | None, str]:
            return {binding.textual_key(): binding.action for binding in pseudocode_keymap().for_tier(tier)}

        for tier in (0, 2):
            keys = actions(tier)
            assert keys["minus"] == keys["plus"] == "toggle_fold"
            # Shift+- reaches a terminal as "_", which stays the negation toggle
            assert keys["underscore"] == "neg_constant"
        assert actions(2)["ctrl+shift+minus"] == "fold_all" and actions(2)["ctrl+shift+plus"] == "unfold_all"
        assert actions(0)["alt+minus"] == "fold_all" and actions(0)["alt+plus"] == "unfold_all"


if __name__ == "__main__":
    unittest.main()
