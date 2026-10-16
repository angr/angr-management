"""
The toolkit-neutral pieces of angrmanagement.present: key bindings, menus, colours, table helpers and the view
bookkeeping. They need no project and no window.
"""

# pylint: disable=no-self-use,protected-access

from __future__ import annotations

import re
import unittest

from textual import events
from textual._xterm_parser import XTermParser

from angrmanagement.config.color import Color
from angrmanagement.config.color_schemes import COLOR_SCHEMES
from angrmanagement.logic.view_manager import BaseViewManager, default_position
from angrmanagement.present.keymap import (
    KITTY_KEYBOARD_TIER,
    Binding,
    Chord,
    Keymap,
    global_keymap,
    table_keymap,
)
from angrmanagement.present.menus import Menu, MenuEntry, MenuSeparator, find_entry, mnemonic_of, strip_mnemonic
from angrmanagement.present.tables import Column, ListTableModel, compile_filter, wildcard_to_regex
from angrmanagement.present.theme import CUSTOM_SCHEME_NAME, StyleSpec, Theme, scheme_colors, scheme_names

# the bytes a terminal without the kitty keyboard protocol sends for each chord the keymaps use
LEGACY_BYTES = {
    "Ctrl+O": "\x0f",
    "Ctrl+W": "\x17",
    "Ctrl+L": "\x0c",
    "Ctrl+S": "\x13",
    "Ctrl+N": "\x0e",
    "Ctrl+B": "\x02",
    "Ctrl+P": "\x10",
    "Ctrl+G": "\x07",
    "Ctrl+C": "\x03",
    "Ctrl+\\": "\x1c",
    "Ctrl+PgDown": "\x1b[6;5~",
    "Ctrl+PgUp": "\x1b[5;5~",
    "Ctrl+Shift+Left": "\x1b[1;6D",
    "Ctrl+Shift+Up": "\x1b[1;6A",
    "Alt+T": "\x1bt",
    "Alt+S": "\x1bs",
    "Alt+O": "\x1bo",
    "Alt+L": "\x1bl",
    "Alt+E": "\x1be",
    "Alt+R": "\x1br",
    "Alt+K": "\x1bk",
    "Alt+M": "\x1bm",
    "Alt+H": "\x1bh",
    "Alt+V": "\x1bv",
    "F2": "\x1bOQ",
    "F4": "\x1bOS",
    "F5": "\x1b[15~",
    "F7": "\x1b[18~",
    "F9": "\x1b[20~",
    "F10": "\x1b[21~",
    "F12": "\x1b[24~",
    "Shift+F10": "\x1b[21;2~",
    "Up": "\x1b[A",
    "Shift+Up": "\x1b[1;2A",
    "PgDown": "\x1b[6~",
    "Home": "\x1b[H",
    "Return": "\r",
    "Esc": "\x1b",
    "X": "x",
    "Del": "\x1b[3~",
    # chords a legacy terminal sends but Textual reads as something else
    "Alt+F": "\x1bf",
    "Alt+B": "\x1bb",
    "Alt+1": "\x1b1",
    "Alt+,": "\x1b,",
    "Ctrl+Alt+F": "\x1b\x06",
    "Shift+F3": "\x1b[1;2R",
    "Ctrl+M": "\r",
    "Ctrl+I": "\t",
    "Ctrl+Shift+P": "\x10",
}


def legacy_keys(data: str) -> list[str]:
    """The keys Textual reports for bytes from a legacy terminal."""
    parser = XTermParser()
    keys = [e.key for e in parser.feed(data) if isinstance(e, events.Key)]
    keys += [e.key for e in parser.feed("") if isinstance(e, events.Key)]
    return keys


class TestChord(unittest.TestCase):
    """Chords parse from Qt's notation and convert to Textual's key names."""

    def test_parse_and_print(self):
        for text in ("Ctrl+Shift+P", "Ctrl+,", "F4", "Alt+H", "Shift+F3", "Ctrl++", "X"):
            assert str(Chord.parse(text)) == text

    def test_textual_names(self):
        assert Chord.parse("Ctrl+Shift+P").to_textual() == "ctrl+shift+p"
        assert Chord.parse("Ctrl+,").to_textual() == "ctrl+comma"
        assert Chord.parse("Ctrl+Alt+F").to_textual() == "alt+ctrl+f"
        assert Chord.parse("Shift+P").to_textual() == "P"
        assert Chord.parse("Return").to_textual() == "enter"
        assert Chord.parse("Ctrl+PgDown").to_textual() == "ctrl+pagedown"
        assert Chord.parse("Ctrl+\\").to_textual() == "ctrl+backslash"

    def test_qkeysequence_matches_qt(self):
        from PySide6.QtGui import QKeySequence  # pylint: disable=import-outside-toplevel

        for text in ("Ctrl+O", "Ctrl+Shift+S", "Ctrl+,", "F4", "Alt+H"):
            assert Chord.parse(text).to_qkeysequence() == QKeySequence(text)

    def test_legacy_reportable_agrees_with_the_textual_parser(self):
        # the claim is about what Textual reports, so check it against Textual's own parser
        for text, data in LEGACY_BYTES.items():
            chord = Chord.parse(text)
            reported = legacy_keys(data) == [chord.to_textual()]
            assert chord.legacy_reportable() == reported, (text, legacy_keys(data), chord.to_textual())

    def test_every_tier_zero_binding_is_reportable(self):
        for keymap in (global_keymap(), table_keymap()):
            for binding in keymap.for_tier(0):
                for chord in binding.chords:
                    assert chord.legacy_reportable(), binding
                    if str(chord) in LEGACY_BYTES:
                        assert legacy_keys(LEGACY_BYTES[str(chord)]) == [chord.to_textual()], binding


class TestKeymap(unittest.TestCase):
    """Bindings that need the kitty keyboard protocol say so and name an alternative."""

    def test_tiers_match_reportability(self):
        for binding in global_keymap():
            needs_kitty = not all(chord.legacy_reportable() for chord in binding.chords)
            assert (binding.tier == KITTY_KEYBOARD_TIER) == needs_kitty, binding

    def test_alternatives_replace_kitty_chords_on_tier_zero(self):
        keymap = global_keymap()
        assert keymap.chord_for("command_palette", 0) == "Ctrl+P"
        assert keymap.chord_for("command_palette", KITTY_KEYBOARD_TIER) == "Ctrl+Shift+P"
        assert keymap.chord_for("next_tab", 0) == "Ctrl+PgDown"
        assert keymap.chord_for("open_file", 0) == "Ctrl+O"
        # no alternative: absent on tier 0
        assert keymap.chord_for("raise_view_by_index", 0, (0,)) is None
        assert keymap.chord_for("raise_view_by_index", KITTY_KEYBOARD_TIER, (0,)) == "Alt+1"

    def test_effective_shortcut_of_menu_entries(self):
        keymap = global_keymap()
        assert keymap.effective_shortcut("Ctrl+Shift+P", 0) == "Ctrl+P"
        assert keymap.effective_shortcut("Ctrl+Shift+P", 2) == "Ctrl+Shift+P"
        assert keymap.effective_shortcut("Ctrl+O", 0) == "Ctrl+O"
        # a chord no binding names and no legacy terminal reports has no stand-in
        assert keymap.effective_shortcut("Ctrl+=", 0) is None

    def test_no_chord_is_bound_twice(self):
        for tier in (0, KITTY_KEYBOARD_TIER):
            chords = [b.textual_key() for b in global_keymap().for_tier(tier) if not b.is_sequence]
            assert len(chords) == len(set(chords)), tier

    def test_sequences(self):
        binding = Binding("Shift, Shift", "goto_palette")
        assert binding.is_sequence
        assert binding.textual_key() is None
        assert [str(c) for c in binding.chords] == ["Shift", "Shift"]
        assert len(Keymap("x", [binding])) == 1


class TestMenus(unittest.TestCase):
    """Menus are data; entries run their actions and keep their checked state without Qt."""

    def test_mnemonics(self):
        assert strip_mnemonic("&File") == "File"
        assert strip_mnemonic("Save && quit") == "Save & quit"
        assert mnemonic_of("S&ave angr database as...") == "a"
        assert mnemonic_of("Save && &quit") == "q"
        assert mnemonic_of("No mnemonic") is None

    def test_trigger(self):
        ran = []
        entry = MenuEntry("&Run", lambda: ran.append("run"))
        entry.trigger()
        assert ran == ["run"]
        entry.disable()
        entry.trigger()
        assert ran == ["run"]

    def test_checkable_entry(self):
        seen = []
        entry = MenuEntry("Toggle", seen.append, checkable=True, checked=False)
        entry.trigger()
        assert entry.checked is True
        entry.trigger()
        assert seen == [True, False]

    def test_items_normalize_tuples_and_none(self):
        menu = Menu("M", [("A", lambda: None), None, ("Sub", [("B", lambda: None)])])
        items = menu.items()
        assert isinstance(items[0], MenuEntry)
        assert isinstance(items[1], MenuSeparator)
        assert isinstance(items[2], Menu)
        assert find_entry(menu, "B") is not None


class TestTheme(unittest.TestCase):
    """Style keys resolve to the scheme's colours."""

    def test_schemes(self):
        assert scheme_names() == [*sorted(COLOR_SCHEMES), CUSTOM_SCHEME_NAME]
        dark = scheme_colors("Dark")
        assert dark["palette_base"] == COLOR_SCHEMES["Dark"]["palette_base"]
        # keys the dark scheme leaves out come from the base scheme
        missing = set(COLOR_SCHEMES["Light"]) - set(COLOR_SCHEMES["Dark"])
        for key in missing:
            assert dark[key] == COLOR_SCHEMES["Light"][key]

    def test_style_keys(self):
        theme = Theme.from_scheme("Light")
        assert theme.style("function_table_plt_color") == StyleSpec(fg=Color(0x00, 0x80, 0x00))
        combined = theme.style("function_table_plt_color function_table_signature_bg_color")
        assert combined.fg == Color(0x00, 0x80, 0x00) and combined.bg == Color(0xAA, 0xFF, 0xFF)
        assert theme.style("table.error").fg == Color(0xC0, 0x00, 0x00)
        assert theme.style("no_such_key").is_plain
        assert not theme.is_dark
        assert Theme.from_scheme("Dark").is_dark

    def test_custom_reads_the_configuration(self):
        theme = Theme.from_scheme(CUSTOM_SCHEME_NAME)
        assert "function_table_color" in theme.colors


class TestTableHelpers(unittest.TestCase):
    """The filter helpers and the list model."""

    def test_wildcards_match_like_qt(self):
        from PySide6.QtCore import QRegularExpression  # pylint: disable=import-outside-toplevel

        options = QRegularExpression.WildcardConversionOption.UnanchoredWildcardConversion
        samples = ["", "hello", "Hello World", "a/b", "a.b", "abc", "[x]", "lib64/ld-linux.so.2", "a+b", "x?y"]
        for pattern in ("*", "h*o", "?ello", "a*b", "a.b", "[a-c]b?", "[!a]bc", "*/*", "a+b", "x\\?y", "ld-*"):
            qt = QRegularExpression(QRegularExpression.wildcardToRegularExpression(pattern, options))
            qt.setPatternOptions(QRegularExpression.PatternOption.CaseInsensitiveOption)
            ours = re.compile(wildcard_to_regex(pattern), re.IGNORECASE)
            for sample in samples:
                assert bool(qt.match(sample).hasMatch()) == bool(ours.search(sample)), (pattern, sample)

    def test_compile_filter(self):
        assert compile_filter("")("anything")
        assert compile_filter("HEL*")("hello")
        assert not compile_filter("x*")("hello")
        assert compile_filter("^h.l", regex=True)("hello")
        assert not compile_filter("(", regex=True)("(")

    def test_list_model(self):
        class Model(ListTableModel[tuple]):
            """Rows are (name, size) pairs."""

            COLUMNS = [Column("Name"), Column("Size", align="right")]

            def column_text(self, obj, col):
                return str(obj[col])

            def column_value(self, obj, col):
                return obj[col]

        model = Model()
        changes = []
        model.changed.connect(lambda kind, first, last: changes.append((kind, first, last)))
        model.set_rows([("b", 2), ("a", 10), ("c", 1)])
        model.sort(1, descending=True)
        assert [r[0] for r in model.rows] == ["a", "b", "c"]
        model.filter("a")
        assert model.rows == [("a", 10)]
        model.filter("ab")
        assert model.rows == []
        model.filter("")
        model.append_rows([("d", 0)])
        # sorted rows stay sorted
        assert [r[0] for r in model.rows] == ["a", "b", "c", "d"]
        assert model.cell(0, 1).text == "10" and model.cell(0, 1).sort_key == 10
        assert changes[0] == ("reset", 0, -1)
        assert ("layout", 0, -1) in changes


class TestBaseViewManager(unittest.TestCase):
    """Views are numbered within their category and remembered by focus."""

    class View:
        """A stand-in view."""

        def __init__(self, category, position="center"):
            self.category = category
            self.default_docking_position = position
            self.index = 0
            self.focused = 0

        def on_focused(self):
            self.focused += 1

    def test_bookkeeping(self):
        vm = BaseViewManager(None)
        a, b, c = self.View("disassembly"), self.View("disassembly"), self.View("functions", "left")
        for view in (a, b, c):
            vm.add_view(view)
        assert (a.index, b.index, c.index) == (1, 2, 1)
        assert vm.first_view_in_category("disassembly") is a
        vm.handle_focus_changed(b)
        assert vm.most_recently_focused_view is b and b.focused == 1
        assert vm.current_view_in_category("disassembly") is b
        assert vm.current_tab is b
        vm.remove_view(a)
        d = self.View("disassembly")
        vm.add_view(d)
        # the lowest free number is reused
        assert d.index == 1

    def test_default_positions(self):
        assert default_position("functions") == "left"
        assert default_position("console") == "bottom"
        assert default_position("registers") == "right"
        assert default_position("tracemap") == "top"
        assert default_position("strings") == "center"


if __name__ == "__main__":
    unittest.main()
