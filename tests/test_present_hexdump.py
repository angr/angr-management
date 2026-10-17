"""
The hex view without a toolkit: the grid's addressing, cursor, selection, keys and byte entry (the semantic part of
tests/test_hex_view.py), and the presenter on fauxware: the loader and debugger sources, patching, regions, the byte
clipboard, find, the context menu, keys and commands.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use

from __future__ import annotations

import os
import unittest
from typing import Any

import angr
from angr.knowledge_plugins.patches import Patch

from angrmanagement.data.breakpoint import Breakpoint, BreakpointType
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.headless_workspace import HeadlessWorkspace
from angrmanagement.logic.ui_services import HeadlessServices
from angrmanagement.present.hexdump import (
    BreakpointHighlightRegion,
    HexDataSource,
    HexGrid,
    HexHighlightRegion,
    HexPresenter,
    PatchHighlightRegion,
    ascii_text,
    byte_text,
    hex_keymap,
    register_hex_commands,
)
from angrmanagement.present.menus import Menu, MenuEntry, find_entry, walk_entries

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")


def set_services(services: Any) -> None:
    GlobalInfo.ui_services = services  # pyright: ignore[reportAttributeAccessIssue]


class AnsweringServices(HeadlessServices):
    """Headless services that pick ``button`` in every question and type ``text`` in every prompt."""

    def __init__(self, button: str = "Yes", text: str | None = None) -> None:
        super().__init__()
        self.button = button
        self.text = text
        self.asked: list[str] = []

    def question(self, title: str, text: str, buttons, default: str) -> str:
        self.asked.append(title)
        return self.button

    def prompt_text(self, title: str, label: str, default: str = "") -> str | None:
        self.asked.append(title)
        return self.text

    def ask_form_async(self, form: Any, callback: Any) -> None:
        """Type ``text`` in the form's first field; OK only if the form's check accepts it."""
        self.asked.append(form.title)
        if self.text is None:
            callback(None)
            return
        values = {**form.initial_values(), form.fields[0].key: self.text}
        callback(values if form.checked(values).ok else None)


def captions(menu: Menu) -> list[str]:
    return [entry.text for _path, entry in walk_entries(menu)]


class GridCase(unittest.TestCase):
    def setUp(self):
        self.grid = HexGrid()
        data = bytes(i % 256 for i in range(1024))
        self.grid.set_data(data, start_addr=0x1000)
        self.grid.set_display_num_rows(1024 // 16 + 1)
        self.grid.set_display_offset(0)


class TestGridData(unittest.TestCase):
    def test_set_data(self):
        grid = HexGrid()
        grid.set_data(b"\x00\x01\x02\x03", start_addr=0x400000)
        assert (grid.start_addr, grid.num_bytes, grid.end_addr) == (0x400000, 4, 0x400004)
        grid.set_data(bytes(48), start_addr=0)
        assert grid.num_rows == 3
        grid.set_data(bytes(256), start_addr=0, num_bytes=64)
        assert grid.end_addr == 64

    def test_reads_and_the_default_writer(self):
        grid = HexGrid()
        grid.set_data(b"\xaa\xbb\xcc", start_addr=0x100)
        assert [grid.read(a) for a in (0x100, 0x101, 0x102)] == [0xAA, 0xBB, 0xCC]
        assert grid.write_func is not None and grid.write_func(0x100, 0xFF) is False
        grid.clear()
        assert (grid.num_bytes, grid.start_addr, grid.end_addr) == (0, 0, 0)

    def test_byte_and_ascii_text(self):
        assert byte_text(0x41) == ("41", "disasm_view_printable_byte_color")
        assert byte_text(0x01) == ("01", "disasm_view_unprintable_byte_color")
        assert byte_text("S") == ("SS", "disasm_view_unknown_byte_color")
        assert byte_text("ab") == ("??", "disasm_view_unknown_byte_color")
        assert ascii_text(0x41) == ("A", "disasm_view_printable_character_color")
        assert ascii_text(0x01) == (".", "disasm_view_unprintable_character_color")
        assert ascii_text("?") == ("?", "disasm_view_unknown_character_color")


class TestGridAddressing(GridCase):
    def test_rows_columns_and_addresses(self):
        grid = self.grid
        assert [grid.row_to_addr(r) for r in range(3)] == [0x1000, 0x1010, 0x1020]
        assert grid.row_col_to_addr(2, 8) == 0x1028
        assert grid.addr_to_row_col(0x102F) == (2, 15)
        for addr in (0x1000, 0x1001, 0x100F, 0x1010, 0x10FF):
            assert grid.row_col_to_addr(*grid.addr_to_row_col(addr)) == addr

    def test_display_offset(self):
        grid = self.grid
        grid.set_display_offset(0x43)
        assert grid.display_start_addr == 0x1040
        grid.set_display_offset(-1)
        assert grid.display_start_addr == grid.start_addr
        grid.set_display_num_rows(0)
        assert grid.display_num_rows == 1

    def test_viewport_follows_the_cursor(self):
        grid = self.grid
        grid.set_display_num_rows(4)
        grid.set_cursor(0x1100)
        # the cursor's row is the last one fully shown: the last of the four rows is the one Qt shows in part
        assert grid.display_start_addr == 0x1100 - 2 * 16
        grid.set_cursor(0x1010)
        assert grid.display_start_addr == 0x1010

    def test_scrolling(self):
        grid = self.grid
        grid.set_display_num_rows(4)
        grid.scroll_rows(2)
        assert grid.display_start_addr == 0x1020
        grid.scroll_rows(-5)
        assert grid.display_start_addr == 0x1000
        grid.scroll_to_fraction(0.5)
        assert grid.display_start_addr == 0x1200
        assert grid.scroll_fraction() == 0.5


class TestGridCursor(GridCase):
    def test_cursor_stays_in_range(self):
        grid = self.grid
        assert grid.cursor == 0x1000
        grid.set_cursor(0x0FFF)
        grid.set_cursor(0x1400)  # end_addr is exclusive
        assert grid.cursor == 0x1000
        grid.set_cursor(0x13FF)
        assert grid.cursor == 0x13FF

    def test_selection(self):
        grid = self.grid
        assert grid.get_selection() is None
        grid.set_cursor(0x1020)
        grid.begin_selection()
        grid.set_cursor(0x1010)
        assert grid.get_selection() == (0x1010, 0x1020)
        assert grid.is_selected(0x1015) and not grid.is_selected(0x1021)
        grid.clear_selection()
        assert grid.get_selection() is None

    def test_movement_keys(self):
        grid = self.grid
        grid.set_display_num_rows(4)
        grid.set_cursor(0x1015)
        steps = [("right", 0x1016), ("left", 0x1015), ("down", 0x1025), ("up", 0x1015), ("home", 0x1010)]
        steps += [("end", 0x101F), ("pagedown", 0x101F + 48), ("pageup", 0x101F)]
        for key, expected in steps:
            assert grid.move_cursor(key, False)
            assert grid.cursor == expected, key
        assert not grid.move_cursor("tab", False)
        grid.set_cursor(0x1000)
        grid.move_cursor("left", False)
        assert grid.cursor == 0x1000

    def test_shift_selects(self):
        grid = self.grid
        grid.set_cursor(0x1000)
        grid.move_cursor("right", True)
        grid.move_cursor("right", True)
        assert grid.get_selection() == (0x1000, 0x1002)
        grid.move_cursor("right", False)
        assert grid.get_selection() is None

    def test_click_drag_and_double_click(self):
        grid = self.grid
        grid.click(0x1010, False, False)
        grid.drag_to(0x1013, True)
        assert grid.get_selection() == (0x1010, 0x1013) and grid.ascii_column_active
        grid.click(0x1020, False, True)
        assert grid.get_selection() == (0x1010, 0x1020)
        grid.click(0x1030, False, False)
        assert grid.get_selection() is None
        grid.set_highlight_regions([HexHighlightRegion(None, 0x1028, 0x10)])
        grid.select_region_under_cursor()
        assert grid.get_selection() == (0x1028, 0x1037) and grid.cursor == 0x1028


class TestGridEntry(unittest.TestCase):
    def setUp(self):
        self.memory = bytearray(64)
        self.grid = HexGrid()

        def write(addr: int, value: Any) -> bool:
            self.memory[addr - 0x100] = value
            return True

        self.grid.set_data_callback(write, lambda addr: self.memory[addr - 0x100], 0x100, 64)

    def test_nibbles(self):
        grid = self.grid
        assert grid.type_text("a")
        assert self.memory[0] == 0xA0 and grid.cursor == 0x100 and grid.cursor_nibble == 0
        assert grid.type_text("5")
        assert self.memory[0] == 0xA5 and grid.cursor == 0x101 and grid.cursor_nibble == 1
        assert not grid.type_text("g")

    def test_ascii_column(self):
        grid = self.grid
        grid.toggle_column()
        assert grid.ascii_column_active
        assert grid.type_text("g")
        assert self.memory[0] == ord("g") and grid.cursor == 0x101
        assert not grid.type_text("\r")
        grid.toggle_column()
        assert not grid.ascii_column_active

    def test_regions_turn_active_under_the_cursor(self):
        grid = self.grid
        inside = HexHighlightRegion(None, 0x100, 4, "here")
        outside = HexHighlightRegion(None, 0x120, 4)
        grid.set_highlight_regions([inside, outside])
        assert inside.active and not outside.active
        assert grid.get_active_highlight_regions() == [inside]
        assert grid.tooltip_at(0x102) == "here" and grid.tooltip_at(0x121) == ""


class FauxwareHexCase(unittest.TestCase):
    project: angr.Project

    @classmethod
    def setUpClass(cls):
        cls.project = angr.Project(FAUXWARE, auto_load_libs=False)
        cls.cfg = cls.project.analyses.CFGFast(normalize=True, data_references=True)
        analyses: Any = cls.project.analyses
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
        self.presenter = HexPresenter(self.workspace, self.instance)
        self.grid = self.presenter.grid
        self.grid.set_display_num_rows(40)
        self.loader = self.project.loader

    def tearDown(self):
        self.presenter.close()
        for addr in [p.addr for p in self.project.kb.patches.values()]:
            self.project.kb.patches.remove_patch(addr)
        set_services(self.saved_services)
        self.workspace.job_manager.quit()


class TestLoaderSource(FauxwareHexCase):
    def test_shows_the_loaded_range(self):
        grid = self.grid
        assert (grid.start_addr, grid.end_addr) == (self.loader.min_addr, self.loader.max_addr + 1)
        assert grid.cursor == self.loader.min_addr
        assert [grid.read(self.loader.min_addr + i) for i in range(4)] == list(b"\x7fELF")
        assert self.presenter.status_text() == f"Address: {self.loader.min_addr:08x}"

    def test_status_shows_the_selection(self):
        grid = self.grid
        grid.set_cursor(self.loader.min_addr + 2)
        grid.move_cursor("down", True)
        start = self.loader.min_addr + 2
        assert self.presenter.status_text() == f"Address: [{start:08x}, {start + 16:08x}], 17 bytes selected"

    def test_cfb_regions(self):
        main = self.project.kb.functions["main"]
        self.presenter.jump_to(main.addr)
        regions = self.grid.get_highlight_regions_at_addr(main.addr)
        assert any("push" in (r.get_tooltip() or "") for r in regions)
        self.presenter.set_smart_highlighting_enabled(False)
        assert not self.grid.get_highlight_regions_at_addr(main.addr)
        menu = self.presenter.options_menu()
        entry = find_entry(menu, "Smart highlighting")
        assert isinstance(entry, MenuEntry) and entry.checkable and not entry.checked

    def test_debugger_source_without_a_debugger(self):
        self.presenter.set_data_source(HexDataSource.Debugger)
        assert self.grid.start_addr == 0 and self.grid.end_addr == 0x10000000000000000
        assert self.grid.read(0x400000) == "?"
        assert 0x400000 in self.presenter._data_cache
        assert self.presenter.debugger_memory_write_func(0x400000, 0) is False
        menu = self.presenter.data_source_menu()
        assert [(e.text, e.checked) for _p, e in walk_entries(menu)] == [("Loader", False), ("Debugger", True)]


class TestPatching(FauxwareHexCase):
    def test_typing_patches_the_byte(self):
        addr = self.loader.min_addr + 0x10
        self.presenter.jump_to(addr)
        self.grid.type_text("9")
        self.grid.type_text("0")
        patches = self.project.kb.patches.get_all_patches(addr, 1)
        assert len(patches) == 1 and patches[0].new_bytes == b"\x90"
        assert self.grid.read(addr) == 0x90 and self.grid.cursor == addr + 1
        assert any(isinstance(r, PatchHighlightRegion) for r in self.grid.get_highlight_regions_at_addr(addr))

    def test_auto_patch_extends_and_splits(self):
        presenter = self.presenter
        pm = self.project.kb.patches
        base = self.loader.min_addr + 0x100
        presenter.auto_patch(base, bytearray(b"\x01\x02"))
        presenter.auto_patch(base + 2, bytearray(b"\x03"))  # extends the adjacent patch
        assert [(p.addr, bytes(p.new_bytes)) for p in pm.values()] == [(base, b"\x01\x02\x03")]
        presenter.auto_patch(base + 1, bytearray(b"\xff"))  # inside: updated in place
        assert bytes(pm.get_all_patches(base, 1)[0].new_bytes) == b"\x01\xff\x03"
        presenter.auto_patch(base - 1, bytearray(b"\xaa\xbb"))  # the lower part is overwritten
        assert sorted((p.addr, bytes(p.new_bytes)) for p in pm.values()) == [
            (base - 1, b"\xaa\xbb"),
            (base + 1, b"\xff\x03"),
        ]

    def test_patch_region_menu_split_comment_revert(self):
        set_services(AnsweringServices("Yes", "a comment"))
        base = self.loader.min_addr + 0x200
        self.presenter.project_memory_write_bytearray(base, bytearray(b"\x90\x90\x90\x90"))
        self.presenter.jump_to(base + 2)
        menu = self.presenter.context_menu()
        patch_menu = next(e for e in menu.entries if isinstance(e, Menu) and e.caption.startswith("Patch"))
        assert captions(patch_menu) == ["Split", "Set Comment...", "Revert"]
        split = find_entry(patch_menu, "Split")
        assert split is not None and split.enabled
        split.trigger()
        assert sorted(p.addr for p in self.project.kb.patches.values()) == [base, base + 2]
        region = next(r for r in self.presenter._patch_highlights if r.addr == base)
        region.comment()
        assert region.patch.comment == "a comment"
        region.revert_with_prompt()
        assert [p.addr for p in self.project.kb.patches.values()] == [base + 2]

    def test_merge_and_revert_selected(self):
        set_services(AnsweringServices("Yes"))
        pm = self.project.kb.patches
        base = self.loader.min_addr + 0x300
        pm.add_patch_obj(Patch(base, bytearray(b"\x01\x02")))
        pm.add_patch_obj(Patch(base + 2, bytearray(b"\x03")))
        self.presenter._update_highlight_regions_from_patches()
        self.presenter.jump_to(base)
        self.grid.move_cursor("right", True)
        self.grid.move_cursor("right", True)
        menu = self.presenter.context_menu()
        merge = find_entry(menu, "Merge selected patches")
        assert merge is not None and merge.enabled
        merge.trigger()
        assert [(p.addr, bytes(p.new_bytes)) for p in pm.values()] == [(base, b"\x01\x02\x03")]
        self.grid.update_active_highlight_regions()
        revert = find_entry(self.presenter.context_menu(), "Revert selected patches")
        assert revert is not None
        revert.trigger()
        assert not list(pm.values())

    def test_cancelled_revert_keeps_the_patch(self):
        set_services(AnsweringServices("Cancel"))
        base = self.loader.min_addr + 0x340
        self.presenter.project_memory_write_bytearray(base, bytearray(b"\x90"))
        region = self.presenter._patch_highlights[0]
        region.revert_with_prompt()
        assert [p.addr for p in self.project.kb.patches.values()] == [base]

    def test_copy_and_paste(self):
        presenter = self.presenter
        start = self.loader.min_addr
        presenter.jump_to(start)
        for _ in range(3):
            self.grid.move_cursor("right", True)
        menu = presenter.context_menu()
        copy = find_entry(menu, "Copy 4 bytes")
        assert copy is not None
        copy.trigger()
        assert presenter._clipboard == bytearray(b"\x7fELF")
        presenter.jump_to(start + 0x400)
        paste = find_entry(presenter.context_menu(), "Paste 4 bytes")
        assert paste is not None
        paste.trigger()
        assert [self.grid.read(start + 0x400 + i) for i in range(4)] == list(b"\x7fELF")


class TestBreakpoints(FauxwareHexCase):
    def test_breakpoint_menu_and_region(self):
        start = self.loader.min_addr + 0x20
        self.presenter.jump_to(start)
        self.grid.move_cursor("right", True)
        menu = self.presenter.context_menu()
        read = find_entry(menu, "Break on Read")
        assert read is not None
        read.trigger()
        bps = list(self.instance.breakpoint_mgr.breakpoints)
        assert [(bp.type, bp.addr, bp.size) for bp in bps] == [(BreakpointType.Read, start, 2)]
        region = next(r for r in self.grid.highlighted_regions if isinstance(r, BreakpointHighlightRegion))
        assert region.get_tooltip() == f"Breakpoint 0x{start:x} Read (2 bytes)"
        menu = region.context_menu()
        assert menu is not None and captions(menu) == ["Remove"]
        region.remove()
        assert not list(self.instance.breakpoint_mgr.breakpoints)

    def test_region_of_a_breakpoint_object(self):
        bp = Breakpoint(BreakpointType.Write, 0x401000, 4)
        region = BreakpointHighlightRegion(bp, self.presenter)
        assert (region.addr, region.size) == (0x401000, 4)
        assert region.get_tooltip() == "Breakpoint 0x401000 Write (4 bytes)"


class TestFind(FauxwareHexCase):
    def test_hex_and_text_modes(self):
        presenter = self.presenter
        bar = presenter.find_bar
        assert not presenter.find_bar_is_open()
        presenter.show_find_bar()
        assert presenter.find_bar_is_open()
        assert bar.is_open and bar.mode == "Hex" and not bar.text_options_visible
        bar.set_query("7f 45 4c 46")
        assert presenter._find_matches and presenter._find_matches[0] == (self.loader.min_addr, 4)
        assert self.grid.cursor == self.loader.min_addr
        assert bar.status.startswith("1 of ")
        bar.set_mode("Text")
        bar.set_query("Username")
        assert bar.text_options_visible
        addr, size = presenter._find_matches[0]
        assert size == len("Username") and self.grid.cursor == addr
        assert bytes(self.grid.read(addr + i) for i in range(size)) == b"Username"  # type: ignore[misc]
        bar.set_query("zz-not-in-the-binary")
        assert bar.status == "No matches"
        bar.set_mode("Hex")
        bar.set_query("4g")
        assert bar.error
        bar.close_bar()
        assert not presenter.find_bar_is_open()
        assert not presenter._find_matches and not presenter._find_highlights


class TestKeysAndCommands(FauxwareHexCase):
    def test_keymap(self):
        keymap = hex_keymap()
        actions = {binding.action for binding in keymap}
        for action in actions - {"context_menu"}:
            assert hasattr(self.presenter, action), action
        assert keymap.chord_for("find_previous", 0) == "Shift+N"
        assert keymap.chord_for("find_previous", 2) == "Shift+F3"
        assert self.presenter.keymap.scope == "hex"

    def test_commands_run_on_the_focused_presenter(self):
        register_hex_commands(self.workspace)
        names = {cmd.name for cmd in self.workspace.command_manager.get_commands()}
        assert {"hex_view_show_find_bar", "hex_view_find_next", "hex_view_find_previous"} <= names
        assert [cmd.name for cmd in self.presenter.commands()] == [
            "hex_view_show_find_bar",
            "hex_view_find_next",
            "hex_view_find_previous",
        ]
        view_manager = self.workspace.view_manager
        view_manager.add_view(self.presenter)
        view_manager.handle_focus_changed(self.presenter)
        command = self.workspace.command_manager.get_commands()
        find = next(cmd for cmd in command if cmd.name == "hex_view_show_find_bar")
        assert find.is_visible
        find.run()
        assert self.presenter.find_bar.is_open

    def test_jump_prompt(self):
        set_services(AnsweringServices(text="main"))
        self.presenter.popup_jumpto_dialog()
        assert self.grid.cursor == self.project.kb.functions["main"].addr


if __name__ == "__main__":
    unittest.main()
