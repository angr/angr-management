"""
The rules the small dialogs share between the frontends, on fauxware from angr/binaries: the address box's resolver,
label names, breakpoint sizes, the patch assembler, the hook presets, encryption keys, the Load Binary checks, the
signature match conflicts, the language questions of Run Analysis and the colour schemes of Preferences.
"""

# pylint: disable=missing-class-docstring,no-self-use,unused-argument

from __future__ import annotations

import os
import unittest
from types import SimpleNamespace
from typing import Any

import angr
import cle

from angrmanagement.data.analysis_options import AnalysesConfiguration
from angrmanagement.data.breakpoint import Breakpoint, BreakpointType
from angrmanagement.data.instance import Instance
from angrmanagement.data.jobs import (
    OverviewConfiguration,
    RustSymbolRecoveryConfiguration,
    RustTypeDBLoaderConfiguration,
)
from angrmanagement.data.load_options import (
    LoadChoiceError,
    arch_choices,
    initial_address_texts,
    selection_from_choices,
    symbol_path_entry_error,
)
from angrmanagement.present.analysis_options import option_rows, set_language
from angrmanagement.present.dialogs import (
    EncKeyFormat,
    PatchAssembler,
    address_of_text,
    apply_breakpoint,
    breakpoint_form,
    breakpoint_size,
    encryption_key_form,
    hook_form,
    hook_templates,
    jump_to_form,
    key_of_form,
    label_name,
    parse_encryption_key,
)
from angrmanagement.present.forms import Form, FormField
from angrmanagement.present.preferences import color_entry_names, scheme_entry_values
from angrmanagement.present.signatures import signature_match_conflict, signature_match_rows

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")


class FauxwareCase(unittest.TestCase):
    project: angr.Project

    @classmethod
    def setUpClass(cls) -> None:
        cls.project = angr.Project(FAUXWARE, auto_load_libs=False)
        cls.project.analyses.CFGFast(normalize=True)

    def setUp(self) -> None:
        self.instance = Instance()
        self.instance.project.am_obj = self.project


class TestAddressesAndNames(FauxwareCase):
    def test_the_address_box_takes_hex_then_a_function_then_a_label(self) -> None:
        main = self.project.kb.functions["main"]
        assert address_of_text(self.instance, "40071d") == main.addr
        assert address_of_text(self.instance, "0x40071d") == main.addr
        assert address_of_text(self.instance, "main") == main.addr
        self.project.kb.labels[0x400739] = "before_puts"
        assert address_of_text(self.instance, "before_puts") == 0x400739
        # hex first, as QAddressInput: a name that is also a number is the number
        assert address_of_text(self.instance, "add") == 0xADD
        assert address_of_text(self.instance, "no such thing") is None
        assert address_of_text(Instance(), "main") is None

    def test_jump_to_is_valid_only_for_an_address(self) -> None:
        form = jump_to_form(self.instance)
        assert form.checked({"address": "main"}).text == "Valid"
        check = form.checked({"address": "nothing here"})
        assert (check.ok, check.text) == (False, "Invalid")

    def test_label_names(self) -> None:
        assert label_name(" a_label ") == "a_label"
        assert label_name("") == ""  # the default name
        assert label_name("two words") is None


class TestBreakpoints(FauxwareCase):
    def test_the_form_checks_the_address_and_size_and_sets_the_breakpoint(self) -> None:
        assert breakpoint_size("0x10") == 16 and breakpoint_size("8") == 8 and breakpoint_size("x") is None
        bp = Breakpoint(BreakpointType.Execute, 0x400100)
        form = breakpoint_form(bp, self.instance)
        values = form.initial_values()
        assert values == {"type": BreakpointType.Execute, "addr": "0x400100", "size": "0x1", "comment": ""}
        assert not form.checked({**values, "size": "0"}).ok
        assert not form.checked({**values, "addr": "nowhere"}).ok
        apply_breakpoint(
            bp, {**values, "type": BreakpointType.Read, "addr": "main", "size": "4", "comment": "c"}, self.instance
        )
        assert (bp.type, bp.addr, bp.size, bp.comment) == (BreakpointType.Read, 0x40071D, 4, "c")


class TestPatches(FauxwareCase):
    def test_assembling_pads_warns_and_refuses(self) -> None:
        assembler = PatchAssembler(self.instance, 0x400739)
        assert assembler.initial_text == "call 0x400510" and len(assembler.original_bytes) == 5
        assert assembler.can_assemble
        padded = assembler.assemble("nop", True)
        assert (padded.new_bytes, padded.message, padded.ok) == (b"\x90" * 5, "", True)
        short = assembler.assemble("nop", False)
        assert short.message == "Warning: Patch is shorter than original instruction"
        longer = assembler.assemble("mov rax, 0x1122334455667788", True)
        assert longer.message == "Warning: Patch exceeds original instruction length" and longer.ok
        bad = assembler.assemble("not an instruction", True)
        assert not bad.ok and bad.message.startswith("Error:")
        # the form shows the bytes as it assembles
        check = assembler.form().checked({"asm": "nop", "pad": True, "bytes": ""})
        assert check.values == {"bytes": "90 90 90 90 90"}


class TestHooks(unittest.TestCase):
    def test_presets_and_the_form(self) -> None:
        templates = hook_templates(0x400100)
        assert sorted(templates) == ["assertion", "base", "disable unicorn", "enable unicorn"]
        assert templates["base"].startswith("@project.hook(addr=0x400100, length=0)")
        form = hook_form(0x400100)
        assert [caption for caption, _value in form.field_of("preset").choices] == sorted(templates)
        assert form.changed("preset", {"preset": "base", "code": ""}) == {"code": templates["base"]}


class TestEncryptionKeys(unittest.TestCase):
    KEY = b"\x02\xf53asdf\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    def test_the_formats(self) -> None:
        assert parse_encryption_key("de:ad-be ef") == b"\xde\xad\xbe\xef"
        assert parse_encryption_key(repr(self.KEY)) == self.KEY
        assert parse_encryption_key("hello", EncKeyFormat.ASCII) == b"hello"
        assert parse_encryption_key("hello", EncKeyFormat.HEX) is None
        assert parse_encryption_key("") is None

    def test_the_form(self) -> None:
        form = encryption_key_form("For cart.", "00 11")
        values = form.initial_values()
        check = form.checked(values)
        assert check.ok and check.values["as_hex"] == "Key in hex: 00 11"
        assert key_of_form(values) == b"\x00\x11"
        assert key_of_form(None) is None
        assert not form.checked({**values, "key": "zz", "format": EncKeyFormat.HEX}).ok


class TestLoadChoices(unittest.TestCase):
    def setUp(self) -> None:
        self.ld = cle.Loader(FAUXWARE, perform_relocations=False, load_debug_info=False, auto_load_libs=False)

    def choices(self, **changes: Any) -> dict[str, Any]:
        recommended, _other, ideal = arch_choices(self.ld)
        assert ideal is recommended[0] and ideal.name == "AMD64"
        base = {
            "outer_backend": "<None>",
            "backend": "elf",
            "simos_name": "SimLinux",
            "arch": ideal,
            "auto_load_libs": False,
            "load_debug_info": True,
            "dependencies": [("libc.so.6", False)],
            "address_texts": {"base_addr": None, "entry_addr": None, "offset": None},
        }
        return {**base, **changes}

    def test_the_dialogs_checks_in_order(self) -> None:
        selection = selection_from_choices(**self.choices())
        assert selection.skip_libs == {"libc.so.6"} and selection.outer_backend is None
        for changes, caption in (
            ({"outer_backend": "nonesuch"}, "Incorrect backend selection"),
            ({"backend": ""}, "Incorrect backend selection"),
            ({"simos_name": "Nonesuch"}, "Incorrect OS selection"),
            ({"arch": None}, "Incorrect architecture selection"),
            ({"address_texts": {"base_addr": "zz"}}, "Incorrect base address"),
            ({"address_texts": {"offset": "--"}}, "Incorrect offset"),
        ):
            with self.subTest(caption=caption), self.assertRaises(LoadChoiceError) as raised:
                selection_from_choices(**self.choices(**changes))
            assert raised.exception.caption == caption
        assert selection_from_choices(**self.choices(address_texts={"entry_addr": "0x10"})).entry_addr == 0x10

    def test_addresses_start_on_for_a_blob(self) -> None:
        assert initial_address_texts(self.ld, type(self.ld.main_object)) == (
            False,
            {"entry_addr": hex(self.ld.main_object.entry), "base_addr": "0x400000", "offset": "0x0"},
        )
        assert initial_address_texts(self.ld, cle.Blob) == (
            True,
            dict.fromkeys(("base_addr", "entry_addr", "offset"), "0x0"),
        )

    def test_symbol_path_entries(self) -> None:
        assert symbol_path_entry_error("srv", "") == "Server URL is required for symbol server entries."
        assert symbol_path_entry_error("local", "") == "Path is required for local entries."
        assert symbol_path_entry_error("other", "x") == "Invalid entry type."
        assert symbol_path_entry_error("srv", "https://example.com") is None


class TestSignatureMatches(FauxwareCase):
    def test_a_name_of_its_own_is_a_conflict(self) -> None:
        kb = self.project.kb
        main = kb.functions["main"]
        default = next(f for f in kb.functions.values() if f.is_default_name)
        assert signature_match_conflict(self.instance, main.addr, "other")
        assert not signature_match_conflict(self.instance, main.addr, "main")
        assert not signature_match_conflict(self.instance, default.addr, "other")
        rows = signature_match_rows(self.instance, {default.addr: "a", main.addr: "b"})
        assert rows == sorted([(default.addr, "a", False), (main.addr, "b", True)])


class TestRunAnalysis(unittest.TestCase):
    def test_picking_a_language_asks_about_its_analyses(self) -> None:
        instance = Instance()
        instance.project.am_obj = angr.Project(os.path.join(test_location, "x86_64", "true"), auto_load_libs=False)
        configs = AnalysesConfiguration(
            [
                OverviewConfiguration(instance),
                RustSymbolRecoveryConfiguration(instance),
                RustTypeDBLoaderConfiguration(instance),
            ]
        )
        assert [row.kind for row in option_rows(configs.by_name("overview"))] == ["choice"]
        prompts = set_language(configs, "rust")
        assert [p.title for p in prompts] == ["Enable Rust-specific analyses?"]
        assert "Rust Symbol Recovery" in prompts[0].text or prompts[0].targets
        prompts[0].apply()
        assert all(c.enabled for c in prompts[0].targets)
        # back to C: the Rust analyses are offered to be turned off
        assert [p.title for p in set_language(configs, "c")] == ["Disable Rust-specific analyses?"]
        assert instance.project.am_obj._languages == ["c"]  # pylint:disable=protected-access


class TestPreferences(unittest.TestCase):
    def test_a_scheme_lays_its_colours_over_the_base(self) -> None:
        names = color_entry_names()
        assert "disasm_view_operand_color" in names
        dark = scheme_entry_values("Dark")
        light = scheme_entry_values("Light")
        assert set(light) <= set(dark)
        assert scheme_entry_values("Custom") == {}


class TestForms(unittest.TestCase):
    def test_a_field_kind_must_be_known(self) -> None:
        with self.assertRaises(ValueError):
            FormField("x", "X", "slider")
        form = Form("t", [FormField("a", "A", value="1")])
        assert form.checked({"a": "2"}).ok and not form.changed("a", {"a": "2"})
        assert SimpleNamespace(**form.initial_values()).a == "1"


if __name__ == "__main__":
    unittest.main()
