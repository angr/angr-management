"""
The types view without a toolkit, on fauxware: reading C types as the type editor does, storing them with their
aliases, the lines with member offsets, editing a type and a member, and the presenter with a scripted type editor.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use

from __future__ import annotations

import os
import unittest
from typing import Any

import angr
from angr.sim_type import SimStruct

from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.headless_workspace import HeadlessWorkspace
from angrmanagement.logic.ui_services import HeadlessServices
from angrmanagement.present.types import (
    ParsedTypes,
    TypesPresenter,
    add_types,
    edit_typedef,
    field_number,
    field_text,
    own_typedefs,
    parse_types,
    set_field,
    typedef_lines,
    typedef_text,
    types_keymap,
)

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")


class TypesCase(unittest.TestCase):
    def setUp(self):
        self.project = angr.Project(FAUXWARE, auto_load_libs=False)
        self.arch = self.project.arch
        self.store: Any = self.project.kb.types

    def add(self, text: str) -> None:
        parsed = parse_types(text, self.arch, self.store)
        assert parsed.ok, parsed.error
        add_types(self.store, self.arch, parsed)


class TestParsing(TypesCase):
    def test_definitions_and_a_declaration(self):
        parsed = parse_types("struct foo { int a; char b; }; typedef int myint;", self.arch, self.store)
        assert parsed.ok and not parsed.error
        assert sorted(str(name) for name, _ty in parsed.main) == ["myint", "struct foo"]
        # a declaration is named only with its semicolon (without it the name is lost, as in the Qt editor)
        parsed = parse_types("char *name;", self.arch, self.store)
        assert parsed.ok and parsed.main[0][0] == "name"
        assert parse_types("char *name", self.arch, self.store).main[0][0] is None

    def test_errors(self):
        self.add("struct taken { int a; };")
        parsed = parse_types("struct taken { char b; };", self.arch, self.store)
        assert not parsed.ok and "Redefining" in parsed.error
        # a type defined twice in the text is refused too, not read as its first declaration alone
        parsed = parse_types("struct b { int a; }; struct b { int c; }; struct d { int e; };", self.arch, self.store)
        assert not parsed.ok and "Redefining body of struct b" in parsed.error
        parsed = parse_types("struct foo { int a; ", self.arch, self.store)
        assert not parsed.ok and parsed.error and parsed.error != "No type"
        parsed = parse_types("", self.arch, self.store)
        assert not parsed.ok and parsed.error
        # a single type is wanted, and the text defines two
        parsed = parse_types("struct a { int x; }; struct b { int y; };", self.arch, self.store, editing_single="a")
        assert not parsed.ok and parsed.error.startswith("One type only")


class TestStore(TypesCase):
    def test_add_types_keeps_aliases(self):
        # the Qt test_type_editor.test_wawa scenario, without the dialog
        assert not own_typedefs(self.store)
        self.add("struct wawa{};")
        assert set(self.store.iter_own_keys()) == {"wawa", "struct wawa"}
        self.add("struct foo { struct wawa a; wawa b; int c; };")
        assert [ty.name for ty in own_typedefs(self.store)] == ["wawa", "foo"]
        assert self.store["foo"].type.size == 32
        # a double click on wawa's first line, in Qt
        wawa = self.store["wawa"]
        assert typedef_text(wawa).startswith("typedef struct wawa {")
        parsed = parse_types("struct wawa { int hey; };", self.arch, self.store, editing_single="wawa")
        assert edit_typedef(self.store, wawa, parsed) is None
        assert set(self.store.iter_own_keys()) == {"wawa", "struct wawa", "foo", "struct foo"}
        assert self.store["wawa"].type.size == 32
        assert self.store["foo"].type.size == 96

    def test_lines_have_member_offsets(self):
        self.add("struct pair { int a; long long b; };")
        lines = typedef_lines(self.store["pair"])
        assert lines[0].startswith("00000010  typedef struct pair {")
        assert lines[1].startswith("00000000  ") and lines[1].endswith("int a;")
        assert lines[2].startswith("00000008  ") and lines[2].endswith("long long b;")
        assert lines[3].startswith("00000010  }")

    def test_edit_typedef_renames_unless_taken(self):
        self.add("struct a { int x; }; struct b { int y; };")
        a = self.store["a"]
        warning = edit_typedef(self.store, a, parse_types("typedef int b;", self.arch, self.store, "a"))
        assert warning == "The name b is already taken."
        warning = edit_typedef(self.store, a, parse_types("typedef struct a { int x; } c;", self.arch, self.store))
        assert warning is None and "c" in self.store

    def test_members(self):
        self.add("struct s { int a; char b; };")
        ty: Any = self.store["s"].type
        assert isinstance(ty, SimStruct)
        assert field_number(ty, 1) == 1 and field_number(ty, "b") == 1
        with self.assertRaises(IndexError):
            field_number(ty, 2)
        with self.assertRaises(KeyError):
            field_number(ty, "zz")
        assert field_text(ty, 1) == ("b", "char b")
        changed, warning = set_field(ty, 1, parse_types("short c;", self.arch, self.store, "b"))
        assert changed and warning is None and list(ty.fields) == ["a", "c"]
        changed, warning = set_field(ty, 1, parse_types("long a;", self.arch, self.store, "c"))
        assert changed and warning == "The name a is already used" and list(ty.fields) == ["a", "c"]
        assert set_field(ty, 0, ParsedTypes()) == (False, None)


class TestPresenter(unittest.TestCase):
    def setUp(self):
        self.project = angr.Project(FAUXWARE, auto_load_libs=False)
        self.workspace: Any = HeadlessWorkspace(auto_analyze=False)
        self.instance: Any = self.workspace.main_instance
        self.instance.project.am_obj = self.project
        self.instance.project.am_event()
        self.saved_services = GlobalInfo._ui_services
        GlobalInfo.ui_services = HeadlessServices()  # pyright: ignore[reportAttributeAccessIssue]
        self.presenter = TypesPresenter(self.workspace, self.instance)
        self.answers: list[str | None] = []
        self.asked: list[tuple[str, bool, str | None]] = []
        self.reloads = 0

        def editor(_title, text, multiline, editing_single, predefined, then):
            self.asked.append((text, multiline, editing_single))
            answer = self.answers.pop(0)
            then(None if answer is None else parse_types(answer, self.project.arch, predefined, editing_single))

        def reloaded():
            self.reloads += 1

        self.presenter.type_editor = editor
        self.presenter.on_reloaded = reloaded

    def tearDown(self):
        GlobalInfo.ui_services = self.saved_services  # pyright: ignore[reportAttributeAccessIssue]
        self.workspace.job_manager.quit()

    def test_add_edit_and_lines(self):
        presenter = self.presenter
        presenter.reload()
        assert presenter.caption_text() == "Persistent (global) variable types"
        assert not presenter.typedefs and not presenter.lines()
        self.answers = ["struct p { int a; int b; }; typedef int myint;"]
        presenter.add_types()
        assert self.asked[-1] == ("", True, None)
        assert [ty.name for ty in presenter.typedefs] == ["p", "myint"]
        lines = presenter.lines()
        assert lines[0][:2] == (0, 0) and (-1, -1, "") in lines
        # Enter on a member's line edits the member in the one-line editor
        self.answers = ["char c;"]
        presenter.edit_line(0, 2)
        assert self.asked[-1] == ("int b", False, "b")
        assert list(presenter.typedefs[0].type.fields) == ["a", "c"]
        # on the first line, the whole type in the multi-line editor
        self.answers = [None]
        presenter.edit_line(0, 0)
        assert self.asked[-1][1] is True and self.asked[-1][0].startswith("typedef struct p {")
        # the closing line edits the whole type too, as in Qt; a new body for a struct the project knows is refused
        # ("Redefining body of struct p"), as the Qt editor refused it with an exception
        self.answers = ["typedef struct p { int only; } p;"]
        presenter.edit_line(0, 3)
        assert self.asked[-1][1] is True
        assert list(presenter.typedefs[0].type.fields) == ["a", "c"]
        assert self.reloads >= 2

    def test_a_function_shows_its_local_types(self):
        presenter = self.presenter
        main = self.project.kb.functions.function(name="main")
        if main is None:
            self.project.analyses.CFGFast(normalize=True)
            main = self.project.kb.functions["main"]
        presenter.function = main
        assert presenter.caption_text() == f"Temporary (local) variable types for function {main.addr:#x}"
        assert presenter.current_typestore is self.project.kb.dec_variables[main.addr].types
        presenter.show_persistent_types()
        assert presenter.function.am_none and presenter.current_typestore is self.project.kb.types

    def test_keymap(self):
        actions = {binding.action for binding in types_keymap()}
        assert actions == {"edit_line", "add_types", "show_persistent_types"}


if __name__ == "__main__":
    unittest.main()
