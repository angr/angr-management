from __future__ import annotations

import os
import unittest

import angr
import capstone

from angrmanagement.data.search import (
    BytePattern,
    Searcher,
    SearchError,
    SearchKind,
    SearchQuery,
    SearchScope,
    TextMatcher,
    available_scopes,
)

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestBytePattern(unittest.TestCase):
    """Tests for hex pattern parsing and wildcard matching."""

    def test_parse_plain(self):
        pattern = BytePattern.parse("48 8b 04 25")
        assert bytes(pattern.values) == b"\x48\x8b\x04\x25"
        assert bytes(pattern.masks) == b"\xff\xff\xff\xff"
        assert not pattern.has_wildcards
        assert len(pattern) == 4

    def test_parse_contiguous_and_prefixed(self):
        assert BytePattern.parse("488b0425").values == BytePattern.parse("0x48 0x8b 04 25").values

    def test_parse_wildcards(self):
        pattern = BytePattern.parse("48 ?? 04 ?")
        assert pattern.has_wildcards
        assert bytes(pattern.masks) == b"\xff\x00\xff\x00"

    def test_parse_nibble_wildcards(self):
        pattern = BytePattern.parse("4? ?b")
        assert bytes(pattern.values) == b"\x40\x0b"
        assert bytes(pattern.masks) == b"\xf0\x0f"

    def test_parse_errors(self):
        for bad in ("", "48 8", "zz", "48 gg"):
            with self.assertRaises(SearchError):
                BytePattern.parse(bad)

    def test_find_exact(self):
        data = b"\x00\x01\x48\x8b\x04\x25\x99"
        assert list(BytePattern.parse("48 8b").finditer(data)) == [2]
        assert list(BytePattern.parse("48 8b").finditer(data, base=0x1000)) == [0x1002]

    def test_find_wildcards(self):
        data = b"\x48\x00\x41\x48\xff\x41\x48\xff\x42"
        assert list(BytePattern.parse("48 ?? 41").finditer(data)) == [0, 3]

    def test_find_nibble_wildcard(self):
        data = bytes([0x40, 0x4F, 0x50, 0x41])
        assert list(BytePattern.parse("4?").finditer(data)) == [0, 1, 3]

    def test_find_overlapping(self):
        assert list(BytePattern.parse("aa aa").finditer(b"\xaa\xaa\xaa\xaa")) == [0, 1, 2]

    def test_alignment(self):
        data = b"\xaa" * 8
        assert list(BytePattern.parse("aa").finditer(data, alignment=4)) == [0, 4]
        assert list(BytePattern.parse("aa").finditer(data, base=0x1002, alignment=4)) == [0x1004, 0x1008]


class TestTextMatcher(unittest.TestCase):
    """Tests for the literal/regex text matcher."""

    def test_literal_is_not_regex(self):
        assert TextMatcher("a.c").search("abc") is None
        assert TextMatcher("a.c").search("a.c") is not None

    def test_case_insensitive_by_default(self):
        assert TextMatcher("ABC").search("xxabcxx") is not None
        assert TextMatcher("ABC", case_sensitive=True).search("xxabcxx") is None

    def test_regex(self):
        assert TextMatcher(r"m[o0]v\s+r", regex=True).search("mov rax, rbx") is not None

    def test_bad_regex(self):
        with self.assertRaises(SearchError):
            TextMatcher("(unclosed", regex=True)


class TestSearcher(unittest.TestCase):
    """Tests for the search strategies against a real binary."""

    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(os.path.join(test_location, "x86_64", "true"), auto_load_libs=False)
        cls.cfg = cls.proj.analyses.CFGFast(normalize=True)
        cls.searcher = Searcher(cls.proj, cfg=cls.cfg.model)

    def test_byte_search_finds_elf_header(self):
        query = SearchQuery(SearchKind.BYTES, "7f 45 4c 46")
        results = self.searcher.run(query)
        assert self.proj.loader.main_object.min_addr in [r.addr for r in results]

    def test_byte_search_with_wildcards(self):
        exact = self.searcher.run(SearchQuery(SearchKind.BYTES, "7f 45 4c 46"))
        wild = self.searcher.run(SearchQuery(SearchKind.BYTES, "7f ?? 4c 46"))
        assert {r.addr for r in exact} <= {r.addr for r in wild}

    def test_string_literal_search(self):
        results = self.searcher.run(SearchQuery(SearchKind.STRING, "GLIBC"))
        assert results
        assert all("GLIBC" in r.text for r in results)

    def test_string_regex_search(self):
        results = self.searcher.run(SearchQuery(SearchKind.STRING, r"GLIBC_2\.\d+", regex=True))
        assert results
        literal = self.searcher.run(SearchQuery(SearchKind.STRING, "GLIBC_2."))
        assert {r.addr for r in results} <= {r.addr for r in literal}

    def test_string_case_sensitivity(self):
        assert self.searcher.run(SearchQuery(SearchKind.STRING, "glibc"))
        assert not self.searcher.run(SearchQuery(SearchKind.STRING, "glibc", case_sensitive=True))

    def test_immediate_search_widths(self):
        addr = self.proj.loader.main_object.min_addr
        data = self.proj.loader.memory.load(addr, 8)
        for value_format, size in [("int8", 1), ("int16", 2), ("int32", 4), ("int64", 8)]:
            value = int.from_bytes(data[:size], "little")
            query = SearchQuery(
                SearchKind.IMMEDIATE, hex(value), value_format=value_format, search_code=False, big_endian=False
            )
            results = self.searcher.run(query)
            assert addr in [r.addr for r in results], value_format

    def test_immediate_search_endianness(self):
        addr = self.proj.loader.main_object.min_addr
        data = self.proj.loader.memory.load(addr, 4)
        big = int.from_bytes(data, "big")
        results = self.searcher.run(
            SearchQuery(SearchKind.IMMEDIATE, hex(big), value_format="int32", search_code=False, big_endian=True)
        )
        assert addr in [r.addr for r in results]

    def test_immediate_search_alignment(self):
        query = SearchQuery(SearchKind.IMMEDIATE, "0", value_format="int8", search_code=False, alignment=16)
        assert all(r.addr % 16 == 0 for r in self.searcher.run(query))

    def test_immediate_search_operands(self):
        insn_addr, value = self._find_immediate_operand()
        query = SearchQuery(SearchKind.IMMEDIATE, hex(value), value_format="int32", search_data=False, search_code=True)
        results = self.searcher.run(query)
        assert insn_addr in [r.addr for r in results]
        assert all(r.kind in ("operand", "displacement") for r in results)

    def _find_immediate_operand(self) -> tuple[int, int]:
        for func in self.searcher.iter_functions(SearchScope("all", "all")):
            for insn in self.searcher._iter_capstone_insns(func):
                for op in insn.insn.operands:
                    if op.type == capstone.CS_OP_IMM and 0 < op.imm < 0x7FFFFFFF:
                        return insn.address, op.imm
        raise AssertionError("no immediate operand found")

    def test_disassembly_text_search(self):
        results = self.searcher.run(SearchQuery(SearchKind.DISASSEMBLY, "xor"))
        assert results
        assert all("xor" in r.context for r in results)
        assert all(r.func_addr is not None for r in results)

    def test_disassembly_regex_search(self):
        results = self.searcher.run(SearchQuery(SearchKind.DISASSEMBLY, r"^mov\s+r[a-d]x", regex=True))
        assert results
        assert all(r.context.startswith("mov") for r in results)

    def test_decompilation_search_only_uses_cache(self):
        # nothing has been decompiled yet, so there is nothing to search
        assert self.searcher.run(SearchQuery(SearchKind.DECOMPILATION, "return")) == []

    def test_scope_restricts_results(self):
        scopes = available_scopes(self.proj)
        text_scope = next(s for s in scopes if s.name == "Section: .text")
        results = self.searcher.run(SearchQuery(SearchKind.BYTES, "48", scope=text_scope))
        assert results
        assert all(text_scope.start <= r.addr < text_scope.start + text_scope.size for r in results)

    def test_function_scope(self):
        func = self.proj.kb.functions["main"]
        scope = SearchScope("main", "function", func_addr=func.addr)
        results = self.searcher.run(SearchQuery(SearchKind.DISASSEMBLY, "mov", scope=scope))
        assert results
        assert {r.func_addr for r in results} == {func.addr}

    def test_max_results(self):
        query = SearchQuery(SearchKind.BYTES, "00", max_results=7)
        assert len(self.searcher.run(query)) == 7

    def test_invalid_queries_raise(self):
        for query in [
            SearchQuery(SearchKind.BYTES, "zz"),
            SearchQuery(SearchKind.IMMEDIATE, "not-a-number"),
            SearchQuery(SearchKind.DISASSEMBLY, "(", regex=True),
        ]:
            with self.assertRaises(SearchError):
                self.searcher.run(query)

    def test_available_scopes(self):
        names = [s.name for s in available_scopes(self.proj, current_func_addr=0x400000)]
        assert names[0] == "Entire address space"
        assert "Main object" in names
        assert "Section: .text" in names
        assert any(n.startswith("Current function") for n in names)
        assert available_scopes(None) == [available_scopes(None)[0]]


if __name__ == "__main__":
    unittest.main()
