"""
The source viewer's model, for either frontend: which lines of which source files the binary's debug information maps
to which addresses, and the find and avoid points set on lines for symbolic execution.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sortedcontainers import SortedDict


class SourceMap:
    """The lines of the source files and their addresses, from a loaded object's ``addr_to_line``."""

    def __init__(self, addr_to_line: SortedDict | None = None) -> None:
        self.addr_to_line: SortedDict | None = None
        #: (file name, line) -> the addresses of the line
        self.line_to_addr: dict[tuple[str, int], list[int]] = defaultdict(list)
        self.file_list: set[str] = set()
        if addr_to_line is not None:
            self.load(addr_to_line)

    def load(self, addr_to_line: SortedDict) -> None:
        self.addr_to_line = addr_to_line  # {(filename, line.state.line), ...}
        self.line_to_addr = defaultdict(list)
        self.file_list = set()
        for addr, lines in self.addr_to_line.items():
            if not lines:
                continue
            filename, line = next(iter(lines))  # take the first line and ignore the rest
            self.file_list.add(filename)
            self.line_to_addr[(filename, line)].append(addr)

    def valid_lines(self, filename: str) -> set[int]:
        """The lines of ``filename`` that have addresses: those a find or avoid point can be set on."""
        return {line for (fn, line) in self.line_to_addr if fn == filename}


def symexec_view_of(workspace: Any) -> Any:
    return workspace.view_manager.first_view_in_category("symexec")


def add_point(workspace: Any, source_map: SourceMap, filename: str, line: int, typ: str) -> str:
    """
    Make the addresses of ``line`` find (``typ`` "find") or avoid points of symbolic execution; returns the marker's
    description, the addresses one per line, or "" when there is no symbolic execution view.
    """
    symexec_view = symexec_view_of(workspace)
    if not symexec_view:
        return ""
    address_list = source_map.line_to_addr[(filename, line)]
    for addr in address_list:
        if typ == "find":
            symexec_view.find_addr_in_exec(addr)
        else:
            symexec_view.avoid_addr_in_exec(addr)
    return "\n".join([(f"0x{i:x}") for i in address_list])


def remove_point(workspace: Any, source_map: SourceMap, filename: str, line: int) -> None:
    symexec_view = symexec_view_of(workspace)
    if not symexec_view:
        return
    for addr in source_map.line_to_addr[(filename, line)]:
        symexec_view.remove_find_addr_in_exec(addr)
        symexec_view.remove_avoid_addr_in_exec(addr)


def read_source(path: str) -> str | None:
    """The text of a source file, or None when it cannot be read (the debug information names where it was built)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def comment_of(line_text: str) -> tuple[str, str | None]:
    """A line split at its ``//`` comment: the code, and the comment or None when it has none."""
    parts = line_text.rsplit("//", 1)
    if len(parts) == 1:
        return line_text, None
    return parts[0], parts[1]


def with_comment(line_text: str, comment: str) -> str:
    """The line with its ``//`` comment set to ``comment``, as the Qt editor's comment command writes it."""
    code, old = comment_of(line_text)
    if old is None:
        return f"{line_text} // {comment}"
    return f"{code}//{comment}"


__all__ = ["SourceMap", "add_point", "comment_of", "read_source", "remove_point", "with_comment"]
