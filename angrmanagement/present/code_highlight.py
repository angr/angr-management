"""
Pseudocode highlighting without a toolkit.

The decompiler's text has no styles of its own. Two things give it some: the position map, which says which node of the
structured code each run of characters belongs to (a variable, a call, a type...), and a small lexer that finds
strings, comments and the keywords of the flavor (C, Rust or Go). :func:`highlight_line` runs both over one line and
returns what the Qt highlighter used to apply as it went: a list of ``(start, count, kind)`` format writes, where a
later write wins over an earlier one. :func:`resolve_runs` turns those writes into runs of one kind each, the way
``QSyntaxHighlighter.setFormat`` lays them over each other, and :func:`kind_style` names the style key of a kind for a
frontend's theme.

The kinds are the names of the Qt view's formats (``qccode_highlighter.FORMATS``): normal, keyword, quotation,
function, library_function, comment, variable, type, label and global_variable.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from angr.analyses.decompiler.structured_codegen import FunctionCallNode, FunctionNode, LabelNode, VariableNode
from angr.sim_type import SimType
from angr.sim_variable import SimMemoryVariable

from angrmanagement.config.font import FontStyle

if TYPE_CHECKING:
    from collections.abc import Sequence

#: A format write: start column, how many characters, and the kind.
FormatWrite = tuple[int, int, str]

#: The kinds, in the order the Qt highlighter's FORMATS lists them.
CODE_KINDS = (
    "normal",
    "keyword",
    "quotation",
    "function",
    "library_function",
    "comment",
    "variable",
    "type",
    "label",
    "global_variable",
)

#: The colour, weight and slant configuration entries of each kind; a library function has the function's font.
KIND_ENTRIES: dict[str, tuple[str, str, str]] = {
    "keyword": ("pseudocode_keyword_color", "pseudocode_keyword_weight", "pseudocode_keyword_style"),
    "quotation": ("pseudocode_quotation_color", "pseudocode_quotation_weight", "pseudocode_quotation_style"),
    "function": ("pseudocode_function_color", "pseudocode_function_weight", "pseudocode_function_style"),
    "library_function": (
        "pseudocode_library_function_color",
        "pseudocode_function_weight",
        "pseudocode_function_style",
    ),
    "comment": ("pseudocode_comment_color", "pseudocode_comment_weight", "pseudocode_comment_style"),
    "variable": ("pseudocode_variable_color", "pseudocode_variable_weight", "pseudocode_variable_style"),
    "type": ("pseudocode_types_color", "pseudocode_types_weight", "pseudocode_types_style"),
    "label": ("pseudocode_label_color", "pseudocode_label_weight", "pseudocode_label_style"),
    "global_variable": (
        "pseudocode_global_variable_color",
        "pseudocode_global_variable_weight",
        "pseudocode_global_variable_style",
    ),
}

#: A weight from this one up shows as bold in a terminal (QFont.Weight.DemiBold).
BOLD_WEIGHT = 600


def node_kind(obj: Any) -> str:
    """The kind of the text of a node of the structured code: the key of the format the highlighters draw it in."""
    if isinstance(obj, SimType):
        return "type"
    if isinstance(obj, FunctionCallNode):
        callee = getattr(obj, "callee_func", None)
        if callee is not None and (callee.is_simprocedure or callee.is_plt or callee.is_syscall):
            return "library_function"
        return "function"
    if isinstance(obj, FunctionNode):
        return "function"
    if isinstance(obj, LabelNode):
        return "label"
    if isinstance(obj, VariableNode):
        if type(getattr(obj, "variable", None)) is SimMemoryVariable:
            return "global_variable"
        return "variable"
    return "normal"


def _words(kind: str, *words: str) -> list[tuple[str, str]]:
    return [(rf"\b{word}\b", kind) for word in words]


#: The C and C++ rules: NULL as a function, then the keywords. Quotations and comments are found by the lexer.
C_CPP_HIGHLIGHTING_RULES: list[tuple[str, str]] = [
    (r"\bNULL\b", "function"),
    *_words(
        "keyword",
        "auto",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "default",
        "delete",
        "do",
        "else",
        "enum",
        "explicit",
        "extern",
        # false and true are not really keywords, and other highlighters style them differently
        "false",
        "for",
        "friend",
        "goto",
        "if",
        "inline",
        "namespace",
        "new",
        "operator",
        "private",
        "protected",
        "public",
        "register",
        "return",
        "sizeof",
        "static",
        "struct",
        "switch",
        "template",
        "this",
        "true",
        "typedef",
        "typename",
        "union",
        "virtual",
        "volatile",
        "while",
    ),
]

#: The Go rules: the keywords, then the built-in functions and types.
GO_HIGHLIGHTING_RULES: list[tuple[str, str]] = [
    *_words(
        "keyword",
        "break",
        "case",
        "chan",
        "const",
        "continue",
        "default",
        "defer",
        "else",
        "fallthrough",
        "for",
        "func",
        "go",
        "goto",
        "if",
        "import",
        "interface",
        "map",
        "package",
        "range",
        "return",
        "select",
        "struct",
        "switch",
        "type",
        "var",
        "nil",
        "true",
        "false",
        "iota",
    ),
    *_words(
        "function",
        "append",
        "cap",
        "clear",
        "close",
        "complex",
        "copy",
        "delete",
        "imag",
        "len",
        "make",
        "max",
        "min",
        "new",
        "panic",
        "print",
        "println",
        "real",
        "recover",
        "any",
        "error",
        "bool",
        "byte",
        "rune",
        "string",
        "int",
        "int8",
        "int16",
        "int32",
        "int64",
        "uint",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "uintptr",
        "float32",
        "float64",
        "complex64",
        "complex128",
    ),
]

#: The Rust rules: keywords, reserved and weak keywords, and the common values styled as keywords.
RUST_HIGHLIGHTING_RULES: list[tuple[str, str]] = _words(
    "keyword",
    "as",
    "async",
    "await",
    "break",
    "const",
    "continue",
    "crate",
    "dyn",
    "else",
    "enum",
    "extern",
    "false",
    "fn",
    "for",
    "if",
    "impl",
    "in",
    "let",
    "loop",
    "match",
    "mod",
    "move",
    "mut",
    "pub",
    "ref",
    "return",
    "self",
    "Self",
    "static",
    "struct",
    "super",
    "trait",
    "true",
    "type",
    "unsafe",
    "use",
    "where",
    "while",
    # reserved keywords
    "abstract",
    "become",
    "box",
    "do",
    "final",
    "gen",
    "macro",
    "override",
    "priv",
    "try",
    "typeof",
    "unsized",
    "virtual",
    "yield",
    # weak keywords
    "'static",
    "marco_rules",
    "raw",
    "safe",
    "union",
    # common types and values that are not keywords
    "None",
    "Some",
    "Ok",
    "Err",
)


def rules_for_flavor(flavor: str | None) -> list[tuple[str, str]]:
    """The keyword rules of a decompilation flavor: Rust, Go, or C for anything else."""
    if flavor == "rust":
        return RUST_HIGHLIGHTING_RULES
    if flavor == "go":
        return GO_HIGHLIGHTING_RULES
    return C_CPP_HIGHLIGHTING_RULES


def highlight_line(
    text: str, start_pos: int, posmap: Any, flavor: str | None, in_comment: bool
) -> tuple[list[FormatWrite], bool]:
    """
    The format writes of one line of pseudocode, in the order they apply, and whether a ``/* */`` comment is still open
    at its end.

    :param text:        The line, without its newline.
    :param start_pos:   Where the line starts in the text the position map indexes.
    :param posmap:      The codegen's ``map_pos_to_node``, or None.
    :param flavor:      The decompilation flavor, which picks the keyword rules.
    :param in_comment:  Whether the previous line ended inside a ``/* */`` comment.
    """
    writes: list[FormatWrite] = []
    mark_in = 0
    quote_status = False
    quote_mark = None
    escape_counter = 0
    for col, _ in enumerate(text):
        if quote_status:
            if escape_counter:
                escape_counter -= 1
            elif text[col] == "\\":
                escape_counter = 1
            elif text[col] == quote_mark:
                quote_status = False
                mark_out = col + 1
                writes.append((mark_in, mark_out - mark_in, "quotation"))
                text = text[:mark_in] + " " * (mark_out - mark_in) + text[mark_out:]
        elif in_comment:
            if text[col : col + 2] == "*/":
                mark_out = col + 2
                in_comment = False
                writes.append((mark_in, mark_out - mark_in, "comment"))
                text = text[:mark_in] + " " * (mark_out - mark_in) + text[mark_out:]
        elif text[col] in ('"', "'"):
            mark_in = col
            quote_status = True
            quote_mark = text[col]
        elif text[col : col + 2] == "/*":
            mark_in = col
            in_comment = True
        elif text[col : col + 2] == "//":
            # a line comment: format the rest of the line and stop
            mark_in = col
            mark_out = len(text)
            writes.append((mark_in, mark_out - mark_in, "comment"))
            text = text[:mark_in] + " " * (mark_out - mark_in) + text[mark_out:]
            break
    if in_comment:
        # still inside a multi-line comment
        mark_out = len(text)
        writes.append((mark_in, mark_out - mark_in, "comment"))
        text = text[:mark_in] + " " * (mark_out - mark_in) + text[mark_out:]

    # the nodes of the structured code; strings and comments are blank by now and skipped
    if posmap is not None:
        current_idx = 0
        while current_idx < len(text):
            if text[current_idx] == " ":
                current_idx += 1
                continue
            element = posmap.get_element(start_pos + current_idx)
            if not element:
                current_idx += 1
                continue
            writes.append((element.start - start_pos, element.length, node_kind(element.obj)))
            # a skipped blank may have put us inside an element, so continue from the element's end
            current_idx = (element.start - start_pos) + element.length

    for pattern, kind in rules_for_flavor(flavor):
        for mo in re.finditer(pattern, text):
            writes.append((mo.start(), mo.end() - mo.start(), kind))
    return writes, in_comment


def resolve_runs(writes: Sequence[FormatWrite], length: int) -> list[tuple[int, int, str]]:
    """
    The writes laid over a line of ``length`` characters as ``QSyntaxHighlighter.setFormat`` lays them: a write that
    starts before the line or past its end is dropped, one that runs past the end is cut, and a later write replaces
    an earlier one. Returns ``(start, count, kind)`` runs in column order; characters no write reaches are in none.
    """
    kinds: list[str | None] = [None] * length
    for start, count, kind in writes:
        if start < 0 or start >= length:
            continue
        for idx in range(start, min(start + count, length)):
            kinds[idx] = kind
    runs: list[tuple[int, int, str]] = []
    idx = 0
    while idx < length:
        kind = kinds[idx]
        end = idx + 1
        while end < length and kinds[end] == kind:
            end += 1
        if kind is not None:
            runs.append((idx, end - idx, kind))
        idx = end
    return runs


def highlight_runs(
    text: str, start_pos: int, posmap: Any, flavor: str | None, in_comment: bool
) -> tuple[list[tuple[int, int, str]], bool]:
    """:func:`highlight_line`, resolved into runs: what the line looks like, and whether a comment is still open."""
    writes, in_comment = highlight_line(text, start_pos, posmap, flavor, in_comment)
    return resolve_runs(writes, len(text)), in_comment


def kind_style(kind: str | None, conf: Any = None) -> str:
    """
    The style key of a kind for a theme: its colour entry, and ``bold`` or ``italic`` when the configuration's weight
    or slant for the kind asks for them. The normal kind and no kind are the view's own text colour (an empty key).
    """
    entries = KIND_ENTRIES.get(kind or "")
    if entries is None:
        return ""
    if conf is None:
        from angrmanagement.config import Conf  # pylint:disable=import-outside-toplevel

        conf = Conf
    color, weight, slant = entries
    parts = [color]
    try:
        if int(conf.entry(weight).value) >= BOLD_WEIGHT:
            parts.append("bold")
        if conf.entry(slant).value in (FontStyle.ITALIC, FontStyle.OBLIQUE):
            parts.append("italic")
    except (KeyError, TypeError, ValueError):
        pass
    return " ".join(parts)


__all__ = [
    "CODE_KINDS",
    "C_CPP_HIGHLIGHTING_RULES",
    "GO_HIGHLIGHTING_RULES",
    "KIND_ENTRIES",
    "RUST_HIGHLIGHTING_RULES",
    "highlight_line",
    "highlight_runs",
    "kind_style",
    "node_kind",
    "resolve_runs",
    "rules_for_flavor",
]
