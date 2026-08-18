from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort
from cle.backends.elf.regions import ELFSection

from angrmanagement.utils import filter_string_for_display

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

    import angr
    from angr.knowledge_base import KnowledgeBase
    from angr.knowledge_plugins.functions import Function

#
# Popular constants, offered as a convenience when composing a value query.
#

MACHINE_EPSILON_DOUBLE_PRECISION = 2.2204460493e-16
MACHINE_EPSILON_SINGLE_PRECISION = 1.1920928955e-07
PI = math.pi
E = math.e
SPEED_OF_LIGHT = 299792458
PLANCK_CONSTANT = 6.62607004e-34
GRAVITATIONAL_CONSTANT = 6.67408e-11
ELEMENTARY_CHARGE = 1.6021766208e-19
BOLTZMANN_CONSTANT = 1.38064852e-23
AVOGADRO_CONSTANT = 6.022140857e23
MAX_INT32 = 2147483647
MAX_INT64 = 9223372036854775807
MAX_UINT32 = 4294967295
MAX_UINT64 = 18446744073709551615
MAX_FLOAT32 = 3.40282347e38
MAX_FLOAT64 = 1.7976931348623157e308

# name -> (value, value format the value should be searched as)
NAMED_CONSTANTS: dict[str, tuple[float | int, str]] = {
    "Machine Epsilon (Double Precision)": (MACHINE_EPSILON_DOUBLE_PRECISION, "double"),
    "Machine Epsilon (Single Precision)": (MACHINE_EPSILON_SINGLE_PRECISION, "float"),
    "Planck Constant": (PLANCK_CONSTANT, "double"),
    "Gravitational Constant": (GRAVITATIONAL_CONSTANT, "double"),
    "Elementary Charge": (ELEMENTARY_CHARGE, "double"),
    "Boltzmann Constant": (BOLTZMANN_CONSTANT, "double"),
    "Avogadro Constant": (AVOGADRO_CONSTANT, "double"),
    "Speed of Light": (SPEED_OF_LIGHT, "int32"),
    "Pi": (PI, "double"),
    "E": (E, "double"),
    "Max int32": (MAX_INT32, "int32"),
    "Max int64": (MAX_INT64, "int64"),
    "Max uint32": (MAX_UINT32, "int32"),
    "Max uint64": (MAX_UINT64, "int64"),
    "Max float32": (MAX_FLOAT32, "float"),
    "Max float64": (MAX_FLOAT64, "double"),
}


class SearchKind(Enum):
    """
    The kinds of search the search core supports.
    """

    BYTES = "Byte pattern"
    STRING = "String"
    IMMEDIATE = "Value"
    DISASSEMBLY = "Disassembly text"
    DECOMPILATION = "Decompilation text"


# value format -> (struct format character, size in bytes)
VALUE_FORMATS: dict[str, tuple[str, int]] = {
    "int8": ("B", 1),
    "int16": ("H", 2),
    "int32": ("I", 4),
    "int64": ("Q", 8),
    "float": ("f", 4),
    "double": ("d", 8),
}


class SearchError(Exception):
    """
    Raised when a query cannot be compiled (bad hex pattern, bad regex, unparsable number, ...).
    """


#
# Byte patterns
#


class BytePattern:
    """A byte sequence with per-byte wildcard support, e.g. ``48 8b ?? 41`` or ``4? 8b``.

    The regex is wrapped in a lookahead so that overlapping occurrences are all reported.
    """

    __slots__ = ("values", "masks", "_regex")

    def __init__(self, values: bytes, masks: bytes) -> None:
        if len(values) != len(masks):
            raise SearchError("Malformed byte pattern")
        if not values:
            raise SearchError("Empty byte pattern")
        self.values = values
        self.masks = masks
        self._regex = re.compile(b"(?=" + self._build_regex(values, masks) + b")", re.DOTALL)

    def __len__(self) -> int:
        return len(self.values)

    @property
    def has_wildcards(self) -> bool:
        return any(m != 0xFF for m in self.masks)

    @staticmethod
    def _build_regex(values: bytes, masks: bytes) -> bytes:
        out = []
        for value, mask in zip(values, masks, strict=True):
            if mask == 0xFF:
                out.append(b"\\x%02x" % value)
            elif mask == 0x00:
                out.append(b".")
            else:
                candidates = b"".join(b"\\x%02x" % b for b in range(256) if b & mask == value)
                out.append(b"[" + candidates + b"]")
        return b"".join(out)

    @classmethod
    def parse(cls, text: str) -> BytePattern:
        """
        Parse a hex pattern. Tokens may be separated by whitespace, and ``?``/``??`` denote a
        wildcard byte. A single ``?`` inside a byte (e.g. ``4?``) denotes a wildcard nibble.
        """
        values = bytearray()
        masks = bytearray()
        for raw_token in text.split():
            token = raw_token
            if token.lower().startswith("0x"):
                token = token[2:]
            if token in ("?", "*"):
                values.append(0)
                masks.append(0)
                continue
            if len(token) % 2 != 0:
                raise SearchError(f"'{raw_token}' does not describe a whole number of bytes")
            for i in range(0, len(token), 2):
                hi, lo = token[i], token[i + 1]
                value = 0
                mask = 0
                for nibble in (hi, lo):
                    value <<= 4
                    mask <<= 4
                    if nibble in "?*":
                        continue
                    if nibble not in "0123456789abcdefABCDEF":
                        raise SearchError(f"'{raw_token}' is not a valid hex pattern")
                    value |= int(nibble, 16)
                    mask |= 0xF
                values.append(value)
                masks.append(mask)
        return cls(bytes(values), bytes(masks))

    @classmethod
    def from_bytes(cls, data: bytes) -> BytePattern:
        return cls(data, b"\xff" * len(data))

    def finditer(self, data: bytes, base: int = 0, alignment: int = 1) -> Iterator[int]:
        """
        Yield the address of every occurrence of this pattern in ``data``, which starts at ``base``.
        """
        for match in self._regex.finditer(data):
            addr = base + match.start()
            if alignment <= 1 or addr % alignment == 0:
                yield addr


#
# Text matching
#


def _is_word_token(token: str) -> bool:
    return bool(re.match(r"\w", token))


def loose_whitespace_regex(text: str) -> str:
    """
    Build a regex source for a literal query that tolerates whitespace differences around
    punctuation: "-0x20" matches capstone's "rbp - 0x20", and "[rbp-0x20]" matches
    "[rbp - 0x20]". Whitespace between two word tokens is still required.
    """
    tokens = re.findall(r"\w+|\S", text)
    if not tokens:
        return re.escape(text)
    parts = [re.escape(tokens[0])]
    for prev, cur in zip(tokens, tokens[1:], strict=False):
        parts.append(r"\s+" if _is_word_token(prev) and _is_word_token(cur) else r"\s*")
        parts.append(re.escape(cur))
    return "".join(parts)


class TextMatcher:
    """A literal-or-regex, case-sensitive-or-not text matcher. With ``loose_whitespace``, a literal pattern tolerates
    whitespace differences around punctuation. This is useful for disassembly text, where renderers disagree on spacing
    inside operands).
    """

    __slots__ = ("pattern", "regex", "case_sensitive", "loose_whitespace", "_regex")

    def __init__(
        self, pattern: str, *, regex: bool = False, case_sensitive: bool = False, loose_whitespace: bool = False
    ) -> None:
        self.pattern = pattern
        self.regex = regex
        self.case_sensitive = case_sensitive
        self.loose_whitespace = loose_whitespace
        flags = 0 if case_sensitive else re.IGNORECASE
        if regex:
            source = pattern
        elif loose_whitespace:
            source = loose_whitespace_regex(pattern)
        else:
            source = re.escape(pattern)
        try:
            self._regex = re.compile(source, flags)
        except re.error as ex:
            raise SearchError(f"Invalid regular expression: {ex}") from ex

    def finditer(self, text: str) -> Iterator[re.Match]:
        return self._regex.finditer(text)

    def search(self, text: str) -> re.Match | None:
        return self._regex.search(text)


#
# Scopes
#


@dataclass(frozen=True)
class SearchScope:
    """
    Where a search should look. ``kind`` is one of ``all``, ``range`` or ``function``.
    """

    name: str
    kind: str = "all"
    start: int | None = None
    size: int | None = None
    func_addr: int | None = None

    @property
    def is_function(self) -> bool:
        return self.kind == "function"


SCOPE_ALL = SearchScope("Entire address space", "all")


def available_scopes(project: angr.Project | None, current_func_addr: int | None = None) -> list[SearchScope]:
    """
    Build the list of scopes offered for a project: the whole address space, each object, each
    section/segment of the main object, and optionally the current function.
    """
    scopes: list[SearchScope] = [SCOPE_ALL]
    if project is None:
        return scopes

    main_object = project.loader.main_object
    if main_object is not None:
        scopes.append(
            SearchScope(
                "Main object",
                "range",
                main_object.min_addr,
                max(main_object.max_addr - main_object.min_addr + 1, 0),
            )
        )
        regions = []
        if hasattr(main_object, "sections"):
            regions = list(main_object.sections)
        elif hasattr(main_object, "segments"):
            regions = list(main_object.segments)
        for idx, region in enumerate(regions):
            size = region.memsize
            if not size or region.only_contains_uninitialized_data:
                continue
            if isinstance(region, ELFSection) and not region.occupies_memory:
                continue
            name = getattr(region, "name", None) or f"segment {idx}"
            scopes.append(SearchScope(f"Section: {name}", "range", region.vaddr, size))

    if current_func_addr is not None:
        name = f"Current function ({current_func_addr:#x})"
        scopes.append(SearchScope(name, "function", func_addr=current_func_addr))
    return scopes


#
# Queries and results
#


@dataclass
class SearchQuery:
    """
    A fully specified search request.
    """

    kind: SearchKind
    text: str
    scope: SearchScope = SCOPE_ALL
    case_sensitive: bool = False
    regex: bool = False
    alignment: int = 1
    value_format: str = "int32"
    big_endian: bool | None = None
    search_data: bool = True
    search_code: bool = True
    encodings: Sequence[str] = ("ascii", "utf-16le")
    min_string_length: int = 4
    decompile_on_demand: bool = False
    max_results: int = 50000


@dataclass
class SearchResult:
    """
    A single hit.
    """

    addr: int
    kind: str
    text: str
    context: str = ""
    func_addr: int | None = None
    func_name: str = ""
    extra: dict = field(default_factory=dict)


#
# The searcher
#


class Searcher:
    """
    Runs :class:`SearchQuery` objects against a loaded project. Contains no Qt or GUI dependency so
    that it can be driven from a job, a test, or a script.
    """

    # Report per-function search progress this often
    PROGRESS_EVERY = 64

    def __init__(self, project: angr.Project, kb: KnowledgeBase | None = None, cfg=None) -> None:
        self.project = project
        self.kb = kb if kb is not None else project.kb
        self.cfg = cfg

    def validate(self, query: SearchQuery) -> None:
        """
        Compile the query without running it. Raises :class:`SearchError` if it is malformed, so
        the UI can report the problem before dispatching a job.
        """
        if query.kind is SearchKind.BYTES:
            BytePattern.parse(query.text)
        elif query.kind is SearchKind.IMMEDIATE:
            self.encode_value(query)
        elif query.regex:
            TextMatcher(query.text, regex=True, case_sensitive=query.case_sensitive)

    def run(self, query: SearchQuery, progress: Callable[[float, str], None] | None = None) -> list[SearchResult]:
        results: list[SearchResult] = []
        for result in self.iter_results(query, progress=progress):
            results.append(result)
            if len(results) >= query.max_results:
                break
        return results

    def iter_results(
        self, query: SearchQuery, progress: Callable[[float, str], None] | None = None
    ) -> Iterator[SearchResult]:
        if not query.text.strip() and query.kind is not SearchKind.STRING:
            return
        dispatch = {
            SearchKind.BYTES: self._search_bytes,
            SearchKind.STRING: self._search_strings,
            SearchKind.IMMEDIATE: self._search_immediates,
            SearchKind.DISASSEMBLY: self._search_disassembly,
            SearchKind.DECOMPILATION: self._search_decompilation,
        }
        yield from dispatch[query.kind](query, progress)

    #
    # Regions and functions
    #

    def iter_regions(self, scope: SearchScope) -> Iterator[tuple[int, bytes]]:
        """
        Yield ``(start_address, data)`` for every readable chunk of memory covered by ``scope``.
        """
        if scope.kind == "function":
            func = self._get_function(scope.func_addr)
            if func is None:
                return
            for block in func.blocks:
                yield block.addr, block.bytes
            return

        if scope.kind == "range" and scope.start is not None and scope.size:
            # clip to the backers so we never fault on unmapped holes inside the range
            end = scope.start + scope.size
            for start, backer in self.project.loader.memory.backers():
                b_end = start + len(backer)
                lo, hi = max(start, scope.start), min(b_end, end)
                if lo < hi:
                    yield lo, bytes(backer[lo - start : hi - start])
            return

        for start, backer in self.project.loader.memory.backers():
            yield start, bytes(backer)

    def scope_size(self, scope: SearchScope) -> int:
        """
        Total number of bytes :meth:`iter_regions` will yield for ``scope``, without copying any.
        """
        if scope.kind == "function":
            func = self._get_function(scope.func_addr)
            return sum(block.size for block in func.blocks) if func is not None else 0

        total = 0
        for start, backer in self.project.loader.memory.backers():
            if scope.kind == "range" and scope.start is not None and scope.size:
                lo = max(start, scope.start)
                hi = min(start + len(backer), scope.start + scope.size)
                total += max(hi - lo, 0)
            else:
                total += len(backer)
        return total

    def iter_functions(self, scope: SearchScope) -> list[Function]:
        if scope.kind == "function":
            func = self._get_function(scope.func_addr)
            return [func] if func is not None else []

        functions = []
        for addr in list(self.kb.functions):
            func = self._get_function(addr)
            if func is None or func.is_simprocedure or func.is_alignment:
                continue
            if (
                scope.kind == "range"
                and scope.start is not None
                and scope.size
                and not scope.start <= func.addr < scope.start + scope.size
            ):
                continue
            functions.append(func)
        return functions

    def _get_function(self, addr: int | None) -> Function | None:
        if addr is None:
            return None
        return self.kb.functions.get_by_addr(addr) if self.kb.functions.contains_addr(addr) else None

    def _function_at(self, addr: int) -> Function | None:
        func = self.kb.functions.floor_func(addr)
        if func is not None and func.addr <= addr < func.addr + max(func.size, 1):
            return func
        return None

    #
    # Byte pattern search
    #

    def _search_bytes(self, query: SearchQuery, progress) -> Iterator[SearchResult]:
        pattern = BytePattern.parse(query.text)
        yield from self._scan_pattern(pattern, query, progress, kind="bytes")

    def _scan_pattern(self, pattern: BytePattern, query: SearchQuery, progress, kind: str) -> Iterator[SearchResult]:
        total = self.scope_size(query.scope) or 1
        scanned = 0
        for start, data in self.iter_regions(query.scope):
            if progress is not None:
                progress(100.0 * scanned / total, f"Scanning {start:#x}")
            for addr in pattern.finditer(data, base=start, alignment=query.alignment):
                offset = addr - start
                matched = data[offset : offset + len(pattern)]
                func = self._function_at(addr)
                yield SearchResult(
                    addr=addr,
                    kind=kind,
                    text=matched.hex(" "),
                    context=self._byte_context(data, offset, len(pattern)),
                    func_addr=func.addr if func is not None else None,
                    func_name=func.name if func is not None else "",
                )
            scanned += len(data)

    @staticmethod
    def _byte_context(data: bytes, offset: int, length: int, window: int = 8) -> str:
        lo = max(0, offset - window)
        hi = min(len(data), offset + length + window)
        return data[lo:hi].hex(" ")

    #
    # String search
    #

    def _search_strings(self, query: SearchQuery, progress) -> Iterator[SearchResult]:
        matcher = TextMatcher(query.text, regex=query.regex, case_sensitive=query.case_sensitive)
        min_len = max(1, query.min_string_length)
        scanners = []
        for encoding in query.encodings:
            if encoding == "ascii":
                scanners.append(("ascii", re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len), "latin-1", 1))
            elif encoding == "utf-16le":
                scanners.append(("utf-16le", re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % min_len), "utf_16_le", 2))

        seen: set[tuple[int, str]] = set()
        total = self.scope_size(query.scope) or 1
        scanned = 0
        for start, data in self.iter_regions(query.scope):
            if progress is not None:
                progress(100.0 * scanned / total, f"Scanning {start:#x}")
            for label, extractor, encoding, _width in scanners:
                for match in extractor.finditer(data):
                    try:
                        decoded = match.group().decode(encoding)
                    except UnicodeDecodeError:
                        continue
                    hit = matcher.search(decoded)
                    if hit is None:
                        continue
                    addr = start + match.start()
                    if (addr, label) in seen:
                        continue
                    seen.add((addr, label))
                    func = self._function_at(addr)
                    yield SearchResult(
                        addr=addr,
                        kind=label,
                        text=filter_string_for_display(hit.group()),
                        context=filter_string_for_display(decoded),
                        func_addr=func.addr if func is not None else None,
                        func_name=func.name if func is not None else "",
                    )
            scanned += len(data)

        yield from self._search_recovered_strings(query, matcher, seen)

    def _search_recovered_strings(
        self, query: SearchQuery, matcher: TextMatcher, seen: set[tuple[int, str]]
    ) -> Iterator[SearchResult]:
        """
        Also report strings that the CFG recovered but the raw-memory scan missed (e.g., strings shorter than the
        minimum length).
        """
        cfg = self.cfg
        memory_data = cfg.memory_data if cfg is not None else None
        if not memory_data:
            return
        for md in list(memory_data.values()):
            if md.sort not in (MemoryDataSort.String, MemoryDataSort.UnicodeString) or md.content is None:
                continue
            label = "ascii" if md.sort == MemoryDataSort.String else "utf-16le"
            if (md.addr, label) in seen:
                continue
            scope = query.scope
            if (
                scope.kind == "range"
                and scope.start is not None
                and scope.size
                and not scope.start <= md.addr < scope.start + scope.size
            ):
                continue
            try:
                decoded = md.content.decode("utf-8" if label == "ascii" else "utf_16_le")
            except UnicodeDecodeError:
                continue
            hit = matcher.search(decoded)
            if hit is None:
                continue
            seen.add((md.addr, label))
            func = self._function_at(md.addr)
            yield SearchResult(
                addr=md.addr,
                kind=f"{label} (known)",
                text=filter_string_for_display(hit.group()),
                context=filter_string_for_display(decoded),
                func_addr=func.addr if func is not None else None,
                func_name=func.name if func is not None else "",
            )

    #
    # Immediate/constant search
    #

    def encode_value(self, query: SearchQuery) -> bytes:
        """
        Encode the query's numeric value into bytes using the requested width and endianness.
        """
        fmt, size = VALUE_FORMATS.get(query.value_format, VALUE_FORMATS["int32"])
        big_endian = query.big_endian
        if big_endian is None:
            big_endian = self.project.arch.memory_endness.endswith("BE")
        prefix = ">" if big_endian else "<"
        try:
            if fmt in ("f", "d"):
                return struct.pack(prefix + fmt, float(query.text))
            value = int(query.text, 0) & ((1 << (size * 8)) - 1)
            return struct.pack(prefix + fmt, value)
        except (ValueError, struct.error) as ex:
            raise SearchError(f"'{query.text}' is not a valid {query.value_format} value: {ex}") from ex

    def _search_immediates(self, query: SearchQuery, progress) -> Iterator[SearchResult]:
        encoded = self.encode_value(query)

        if query.search_data:
            pattern = BytePattern.from_bytes(encoded)
            yield from self._scan_pattern(pattern, query, progress, kind="data")

        if query.search_code and query.value_format not in ("float", "double"):
            _fmt, size = VALUE_FORMATS.get(query.value_format, VALUE_FORMATS["int32"])
            wanted = int(query.text, 0) & ((1 << (size * 8)) - 1)
            yield from self._search_operand_immediates(query, wanted, size, progress)

    def _search_operand_immediates(
        self, query: SearchQuery, wanted: int, size: int, progress
    ) -> Iterator[SearchResult]:
        import capstone  # pylint:disable=import-outside-toplevel

        mask = (1 << (size * 8)) - 1
        functions = self.iter_functions(query.scope)
        total = len(functions) or 1
        for idx, func in enumerate(functions):
            if progress is not None and idx % self.PROGRESS_EVERY == 0:
                progress(100.0 * idx / total, f"Scanning {func.name}")
            for insn in self._iter_capstone_insns(func):
                raw = insn.insn
                operands = raw.operands
                for op in operands:
                    value = None
                    label = "operand"
                    if op.type == capstone.CS_OP_IMM:
                        value = op.imm
                    elif op.type == capstone.CS_OP_MEM:
                        mem = op.mem
                        value = mem.disp if mem is not None else None
                        label = "displacement"
                    if value is None or (value & mask) != wanted:
                        continue
                    yield SearchResult(
                        addr=insn.address,
                        kind=label,
                        text=f"{value:#x}",
                        context=f"{insn.mnemonic} {insn.op_str}".strip(),
                        func_addr=func.addr,
                        func_name=func.name,
                    )
                    break

    #
    # Disassembly text search
    #

    def _search_disassembly(self, query: SearchQuery, progress) -> Iterator[SearchResult]:
        matcher = TextMatcher(query.text, regex=query.regex, case_sensitive=query.case_sensitive, loose_whitespace=True)
        functions = self.iter_functions(query.scope)
        total = len(functions) or 1
        for idx, func in enumerate(functions):
            if progress is not None and idx % self.PROGRESS_EVERY == 0:
                progress(100.0 * idx / total, f"Scanning {func.name}")
            for addr, text in self.iter_instruction_texts(func):
                hit = matcher.search(text)
                if hit is None:
                    continue
                yield SearchResult(
                    addr=addr,
                    kind="insn",
                    text=hit.group(),
                    context=text,
                    func_addr=func.addr,
                    func_name=func.name,
                )

    def iter_instruction_details(self, func: Function) -> Iterator[tuple[int, str, bytes]]:
        """
        Yield ``(address, text, bytes)`` for every instruction of ``func``, without comments.
        """
        for insn in self._iter_capstone_insns(func):
            raw = insn.insn
            raw_bytes = bytes(raw.bytes or b"")
            yield insn.address, f"{insn.mnemonic} {insn.op_str}".strip(), raw_bytes

    def iter_instruction_texts(self, func: Function) -> Iterator[tuple[int, str]]:
        """
        Yield ``(address, text)`` for every instruction of ``func``, including any user comment
        attached to the instruction.
        """
        comments = self.kb.comments
        for addr, text, _ in self.iter_instruction_details(func):
            comment = comments.get(addr) if comments is not None else None
            if comment:
                text = f"{text} ; {comment}"
            yield addr, text

    @staticmethod
    def _iter_capstone_insns(func: Function):
        for block in func.blocks:
            if block.capstone is None:
                continue
            yield from block.capstone.insns

    #
    # Decompilation text search
    #

    def _search_decompilation(self, query: SearchQuery, progress) -> Iterator[SearchResult]:
        matcher = TextMatcher(query.text, regex=query.regex, case_sensitive=query.case_sensitive)
        decompilations = self.kb.decompilations
        if decompilations is None:
            return

        targets: list[tuple[int, str]] = []
        cached_addrs = set()
        for key in list(decompilations.cached):
            if not isinstance(key, tuple) or len(key) != 2:
                continue
            addr, flavor = key
            if query.scope.is_function and addr != query.scope.func_addr:
                continue
            targets.append((addr, flavor))
            cached_addrs.add(addr)

        if query.decompile_on_demand:
            for func in self.iter_functions(query.scope):
                if func.addr not in cached_addrs:
                    targets.append((func.addr, "pseudocode"))

        total = len(targets) or 1
        for idx, (addr, flavor) in enumerate(targets):
            if progress is not None:
                progress(100.0 * idx / total, f"Searching {addr:#x}")
            codegen = self._get_codegen(addr, flavor, decompile=query.decompile_on_demand)
            if codegen is None:
                continue
            text = codegen.text
            if not text:
                continue
            func = self._get_function(addr)
            func_name = func.name if func is not None else ""
            for hit in matcher.finditer(text):
                yield SearchResult(
                    addr=self._codegen_addr(codegen, hit.start(), addr),
                    kind=f"decomp ({flavor})",
                    text=hit.group(),
                    context=self._line_at(text, hit.start()),
                    func_addr=addr,
                    func_name=func_name,
                )

    def _get_codegen(self, addr: int, flavor: str, decompile: bool):
        decompilations = self.kb.decompilations
        cache = decompilations[(addr, flavor)] if (addr, flavor) in decompilations else None  # noqa: SIM401
        if cache is None and decompile:
            func = self._get_function(addr)
            if func is None:
                return None
            self.project.analyses.Decompiler(func, cfg=self.cfg, flavor=flavor, use_cache=True)
            cache = decompilations[(addr, flavor)]
        return cache.codegen if cache is not None else None

    @staticmethod
    def _codegen_addr(codegen, pos: int, fallback: int) -> int:
        """
        Map a position in the generated text back to an instruction address. The position maps hold
        codegen nodes, whose ``ins_addr`` tag is the address we want.
        """
        for attr in ("map_pos_to_addr", "map_pos_to_node"):
            posmap = getattr(codegen, attr, None)
            if posmap is None:
                continue
            node = posmap.get_node(pos)
            if isinstance(node, int):
                return node
            tags = node.tags
            if tags and isinstance(tags.get("ins_addr"), int):
                return tags["ins_addr"]
        return fallback

    @staticmethod
    def _line_at(text: str, pos: int) -> str:
        start = text.rfind("\n", 0, pos) + 1
        end = text.find("\n", pos)
        if end == -1:
            end = len(text)
        return text[start:end].strip()
