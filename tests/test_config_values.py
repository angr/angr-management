"""
The configuration's frontend-neutral values: Color, FontSpec, FontWeight, FontStyle, and the frontend adapter.
"""

# pylint: disable=protected-access,no-self-use

from __future__ import annotations

import importlib.util
import io
import os
import random
import sys
import tempfile
import unittest
from unittest.mock import patch

from angrmanagement import config as config_module
from angrmanagement.config.color import Color
from angrmanagement.config.config_entry import ConfigurationEntry
from angrmanagement.config.config_manager import ConfigurationManager, data_serializers
from angrmanagement.config.font import STYLE_NAMES, WEIGHT_NAMES, FontSpec, FontStyle, FontWeight

needs_qt = unittest.skipIf(importlib.util.find_spec("PySide6") is None, "PySide6 is not installed")


class TestColor(unittest.TestCase):
    """Color parses and writes the configuration file's colour formats."""

    def test_hex_forms(self):
        assert Color.from_hex("abc") == Color(0xAA, 0xBB, 0xCC)
        assert Color.from_hex("#112233") == Color(0x11, 0x22, 0x33, 0xFF)
        assert Color.from_hex("80112233") == Color(0x11, 0x22, 0x33, 0x80)
        # 12 digits: each 16-bit channel divided by 257 and rounded, as QColor does
        assert Color.from_hex("#1234567890ab") == Color(0x12, 0x56, 0x90)
        assert Color.from_hex("#ab00ab00ab00") == Color(0xAA, 0xAA, 0xAA)
        assert Color.from_hex("00ff00ff00ff") == Color(1, 1, 1)

    def test_round_trip_through_the_serializer(self):
        parse, serialize = data_serializers[Color]
        for text, expected in (
            ("123", "ff112233"),
            ("a0b0c0", "ffa0b0c0"),
            ("40a0b0c0", "40a0b0c0"),
            ("ffffeeeedddd", "ffffeedd"),
        ):
            color = parse("option", text)
            assert serialize("option", color) == expected
            assert parse("option", serialize("option", color)) == color

    def test_bad_values_are_refused(self):
        parse, _ = data_serializers[Color]
        for text in ("12", "12345", "1234567", "zz0000", "12zz56", "", 0x123456):
            with self.assertLogs("angrmanagement.config.config_manager", level="ERROR"):
                assert parse("option", text) is None
        with self.assertRaises(ValueError):
            Color(256, 0, 0)

    def test_qcolor_style_accessors(self):
        color = Color(0x10, 0x20, 0x30, 0x40)
        assert (color.red(), color.green(), color.blue(), color.alpha()) == (0x10, 0x20, 0x30, 0x40)
        assert color.name() == "#102030"
        assert color.hex == "40102030"
        assert color.rgb_hex == "102030"
        assert color.isValid()
        assert len({Color(1, 2, 3), Color(1, 2, 3, 255), Color(1, 2, 4)}) == 2

    @needs_qt
    def test_equal_to_qcolor_by_channels(self):
        from PySide6.QtGui import QColor  # pylint: disable=import-outside-toplevel

        assert Color(1, 2, 3) == QColor(1, 2, 3)
        assert Color(1, 2, 3, 4) == QColor(1, 2, 3, 4)
        assert Color(1, 2, 3) != QColor(1, 2, 4)
        assert Color(1, 2, 3, 4).to_qcolor().getRgb() == (1, 2, 3, 4)
        assert Color.from_qcolor(QColor(5, 6, 7, 8)) == Color(5, 6, 7, 8)
        for text in ("123", "112233", "44112233", "111122223333", "ab00ab00ab00", "00ff00ff00ff"):
            assert Color.from_hex(text) == QColor("#" + text), text
        rnd = random.Random(0)
        for _ in range(2000):
            text = f"{rnd.getrandbits(48):012x}"
            assert Color.from_hex(text) == QColor("#" + text), text

    @needs_qt
    def test_lighter_and_darker_follow_qcolor(self):
        from PySide6.QtGui import QColor  # pylint: disable=import-outside-toplevel

        rnd = random.Random(0)
        for _ in range(2000):
            rgba = (rnd.randrange(256), rnd.randrange(256), rnd.randrange(256), rnd.randrange(256))
            color, qcolor = Color(*rgba), QColor(*rgba)
            for factor in (0, 50, 100, 110, 150, 200, 300):
                for method in ("lighter", "darker"):
                    ours = getattr(color, method)(factor).getRgb()
                    theirs = getattr(qcolor, method)(factor).getRgb()
                    assert max(abs(a - b) for a, b in zip(ours, theirs, strict=True)) <= 1, (rgba, method, factor)
        assert Color(0, 0, 0).lighter() == Color(0, 0, 0)
        assert Color(200, 10, 10).darker() == QColor(200, 10, 10).darker()


class TestFont(unittest.TestCase):
    """FontSpec, FontWeight and FontStyle keep the configuration file's font formats."""

    def test_legacy_string_round_trip(self):
        parse, serialize = data_serializers[FontSpec]
        for text in ("11px||DejaVu Sans Mono||400", "9px||Sans Serif||700", "-1px||Some Font||500"):
            spec = parse("option", text)
            assert serialize("option", spec) == text
        assert parse("option", "12||Mono||400") == FontSpec("Mono", 12, 400)
        for bad in ("11px||Mono", "big||Mono||400", "11px||Mono||450", 11):
            with self.assertLogs("angrmanagement.config.config_manager", level="ERROR"):
                assert parse("option", bad) is None

    def test_default_weight_is_what_qfont_gives(self):
        assert FontSpec("DejaVu Sans Mono", 11).to_legacy_string() == "11px||DejaVu Sans Mono||400"

    def test_weight_names(self):
        assert WEIGHT_NAMES == {
            "Thin": 100,
            "ExtraLight": 200,
            "Light": 300,
            "Normal": 400,
            "Medium": 500,
            "DemiBold": 600,
            "Bold": 700,
            "ExtraBold": 800,
            "Black": 900,
        }
        parse, serialize = data_serializers[FontWeight]
        for name, value in WEIGHT_NAMES.items():
            weight = parse("option", name)
            assert isinstance(weight, FontWeight) and weight == value
            assert serialize("option", weight) == name
        assert parse("option", 700) == 700
        with self.assertLogs("angrmanagement.config.config_manager", level="ERROR"):
            assert parse("option", "Heavy") == 500

    def test_style_names(self):
        assert STYLE_NAMES == {
            "StyleNormal": FontStyle.NORMAL,
            "StyleItalic": FontStyle.ITALIC,
            "StyleOblique": FontStyle.OBLIQUE,
        }
        parse, serialize = data_serializers[FontStyle]
        for name, style in STYLE_NAMES.items():
            assert parse("option", name) is style
            assert serialize("option", style) == name
        with self.assertLogs("angrmanagement.config.config_manager", level="ERROR"):
            assert parse("option", "Slanted") is FontStyle.NORMAL

    @needs_qt
    def test_qt_names_match_qfont(self):
        from PySide6.QtGui import QFont  # pylint: disable=import-outside-toplevel

        assert {weight.name: weight.value for weight in QFont.Weight} == WEIGHT_NAMES
        assert {style.name for style in QFont.Style} == set(STYLE_NAMES)
        qfont = FontSpec("DejaVu Sans Mono", 11, 700, FontStyle.ITALIC).to_qfont()
        assert (qfont.family(), qfont.pointSize(), qfont.weight(), qfont.style()) == (
            "DejaVu Sans Mono",
            11,
            QFont.Weight.Bold,
            QFont.Style.StyleItalic,
        )
        assert FontSpec.from_qfont(qfont) == FontSpec("DejaVu Sans Mono", 11, 700, FontStyle.ITALIC)


class _RecordingAdapter:
    """A frontend adapter that wraps stored values in a list and records the conversions."""

    def __init__(self) -> None:
        self.to_calls = []
        self.from_calls = []

    def to_frontend(self, entry_name, value):
        self.to_calls.append(entry_name)
        return ["frontend", value]

    def from_frontend(self, entry_name, value):
        self.from_calls.append(entry_name)
        if isinstance(value, list) and value[:1] == ["frontend"]:
            return value[1]
        return value

    def font_metrics(self, font):
        return (font.size * 2, font.size, font.size * 1.5)

    def default_fonts(self):
        return {"ui_default_font": FontSpec("UI", 8), "tabular_view_font": FontSpec("Table", 7)}


class TestFrontendAdapter(unittest.TestCase):
    """ConfigurationManager hands stored values to the frontend through its adapter."""

    def setUp(self) -> None:
        self.conf = ConfigurationManager()
        self.adapter = _RecordingAdapter()

    def test_headless_values_are_neutral(self):
        assert isinstance(self.conf.disasm_view_background_color, Color)
        assert isinstance(self.conf.disasm_font, FontSpec)
        assert isinstance(self.conf.pseudocode_comment_weight, FontWeight)
        assert self.conf.pseudocode_comment_style is FontStyle.NORMAL
        assert (self.conf.disasm_font_height, self.conf.disasm_font_width, self.conf.disasm_font_ascent) == (1, 1, 1)
        self.conf.init_font_config()
        assert self.conf.ui_default_font == FontSpec("DejaVu Sans Mono", 10)

    def test_reads_are_converted_once_per_value(self):
        self.conf.set_frontend_adapter(self.adapter)
        first = self.conf.palette_window
        assert first == ["frontend", self.conf.entry("palette_window").value]
        assert self.conf.palette_window is first
        assert self.adapter.to_calls == ["palette_window"]

        self.conf.palette_window = Color(1, 2, 3)
        second = self.conf.palette_window
        assert second == ["frontend", Color(1, 2, 3)] and second is not first
        assert self.conf.palette_window is second

        # installing an adapter drops what the previous one converted
        self.conf.set_frontend_adapter(None)
        assert self.conf.palette_window == Color(1, 2, 3)

    def test_assignments_are_converted_back(self):
        self.conf.set_frontend_adapter(self.adapter)
        self.conf.palette_window = ["frontend", Color(9, 9, 9)]
        assert self.adapter.from_calls == ["palette_window"]
        assert self.conf.entry("palette_window").value == Color(9, 9, 9)
        # an int assigned to a weight entry is stored as a FontWeight, so it is saved by name
        self.conf.pseudocode_comment_weight = 700
        assert isinstance(self.conf.entry("pseudocode_comment_weight").value, FontWeight)

    def test_listeners_get_frontend_values(self):
        self.conf.set_frontend_adapter(self.adapter)
        got = []
        self.conf.connect("palette_window", got.append, True)
        self.conf.palette_window = Color(4, 5, 6)
        assert got[-1] == ["frontend", Color(4, 5, 6)]
        self.conf.disconnect("palette_window", got.append)
        self.conf.palette_window = Color(7, 8, 9)
        assert len(got) == 2

    def test_font_metrics_and_defaults_come_from_the_adapter(self):
        self.conf.set_frontend_adapter(self.adapter)
        self.conf.code_font = FontSpec("Mono", 10)
        assert (self.conf.code_font_height, self.conf.code_font_width, self.conf.code_font_ascent) == (20, 10, 15)
        self.conf.init_font_config()
        assert self.conf.entry("ui_default_font").value == FontSpec("UI", 8)
        assert self.conf.entry("tabular_view_font").value == FontSpec("Table", 7)

    def test_save_and_parse_round_trip(self):
        self.conf.pseudocode_comment_weight = FontWeight(700)
        self.conf.pseudocode_comment_style = FontStyle.ITALIC
        self.conf.code_font = FontSpec("Mono", 13, 600)
        # an entry no colour scheme sets, so it is saved
        self.conf.disasm_view_bookmark_color = Color(1, 2, 3, 4)
        out = io.StringIO()
        self.conf.save(out)
        text = out.getvalue()
        assert 'pseudocode_comment_weight = "Bold"' in text
        assert 'pseudocode_comment_style = "StyleItalic"' in text
        assert 'code_font = "13px||Mono||600"' in text
        assert 'disasm_view_bookmark_color = "04010203"' in text
        loaded = ConfigurationManager.parse(io.StringIO(text))
        names = ("pseudocode_comment_weight", "pseudocode_comment_style", "code_font", "disasm_view_bookmark_color")
        for name in names:
            assert loaded.entry(name).value == self.conf.entry(name).value, name

    @needs_qt
    def test_plugin_entries_declared_with_qt_types_become_neutral(self):
        from PySide6.QtGui import QColor, QFont  # pylint: disable=import-outside-toplevel

        entry = ConfigurationEntry("plugin_color", QColor, QColor(1, 2, 3))
        assert entry.type_ is Color and entry.value == Color(1, 2, 3)
        entry = ConfigurationEntry("plugin_font", QFont, QFont("Mono", 9))
        assert entry.type_ is FontSpec and entry.value == FontSpec("Mono", 9)
        entry = ConfigurationEntry("plugin_weight", QFont.Weight, QFont.Weight.Bold)
        assert entry.type_ is FontWeight and entry.value == 700
        entry = ConfigurationEntry("plugin_style", QFont.Style, QFont.Style.StyleItalic)
        assert entry.type_ is FontStyle and entry.value is FontStyle.ITALIC


class TestConfigDirectory(unittest.TestCase):
    """Where the configuration file lives."""

    def test_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "conf")
            with patch.dict(os.environ, {"ANGR_MANAGEMENT_CONFIG_DIR": target}):
                assert config_module._find_config_dir() == target
            assert os.path.isdir(target)

    @unittest.skipUnless(sys.platform.startswith("linux"), "this checks the Linux locations")
    def test_linux_location_is_the_one_qt_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"ANGR_MANAGEMENT_CONFIG_DIR": "", "XDG_CONFIG_HOME": tmp}
            with patch.dict(os.environ, env):
                legacy = os.path.join(tmp, "angr-management")
                assert config_module._legacy_config_dir() == legacy
                # it does not exist yet: platformdirs picks the same directory, and creates it
                assert config_module._find_config_dir() == legacy
                assert os.path.isdir(legacy)
                # now it exists and is kept
                assert config_module._find_config_dir() == legacy

    def test_legacy_directory_wins_when_it_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            legacy = os.path.join(tmp, "legacy")
            os.makedirs(legacy)
            with (
                patch.dict(os.environ, {"ANGR_MANAGEMENT_CONFIG_DIR": ""}),
                patch.object(config_module, "_legacy_config_dir", return_value=legacy),
                patch.object(config_module.platformdirs, "user_config_dir", return_value=os.path.join(tmp, "new")),
            ):
                assert config_module._find_config_dir() == legacy
                os.rmdir(legacy)
                assert config_module._find_config_dir() == os.path.join(tmp, "new")


if __name__ == "__main__":
    unittest.main()
