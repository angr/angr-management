"""
angr:// links on addresses: what a terminal of tier 1 or more shows as a hyperlink (OSC 8) on an address in the
disassembly and on a function or a function's address in the pseudocode.

A link is a ``link:<hex address>`` token among a span's style keys. The terminal frontend's style cache turns it into
a hyperlink to :func:`angr_url` and the theme ignores it, so a frontend that does not know links draws the same text.
The URL is the daemon's ``jumpto`` action (angrmanagement.daemon.url_handler), with this window's client id as its
target when the app is connected to the daemon, so opening the link from the terminal jumps there.
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from angr.analyses.decompiler.structured_codegen import ConstantNode, FunctionCallNode, FunctionNode

from angrmanagement.logic import GlobalInfo
from angrmanagement.present.block_tree.disasm_nodes import ADDRESS_STYLE

#: The style key token that carries a link.
LINK_PREFIX = "link:"
#: The lowest terminal tier that shows links.
LINK_TIER = 1


def angr_url(addr: int, target_id: str | None = None) -> str:
    """The URL of the daemon's jump to ``addr``, in the window ``target_id`` (this one's client id when None)."""
    target_id = target_id if target_id is not None else GlobalInfo.client_id
    query = {"action": "jumpto", "addr": f"0x{addr:x}"}
    if target_id:
        query["target_id"] = target_id
    return "angr://?" + urllib.parse.urlencode(query)


def link_key(addr: int) -> str:
    """The style key token of a link to ``addr``."""
    return f"{LINK_PREFIX}{addr:x}"


def split_link(key: str) -> tuple[str, int | None]:
    """``key`` without its link token, and the token's address (None when it has none)."""
    if LINK_PREFIX not in key:
        return key, None
    addr = None
    rest = []
    for part in key.split():
        if part.startswith(LINK_PREFIX):
            try:
                addr = int(part[len(LINK_PREFIX) :], 16)
            except ValueError:
                continue
        else:
            rest.append(part)
    return " ".join(rest), addr


def with_link(key: str, addr: int | None) -> str:
    """``key`` with a link to ``addr`` added (unchanged when ``addr`` is None)."""
    return f"{key} {link_key(addr)}".strip() if addr is not None else key


def disasm_link_addr(span: Any) -> int | None:
    """The address a disassembly span links to: an address column's instruction, block or data."""
    if ADDRESS_STYLE not in span.style.split():
        return None
    addr = getattr(span.node, "addr", None)
    return addr if isinstance(addr, int) else None


def code_link_addr(node: Any, kb: Any = None) -> int | None:
    """
    The address a pseudocode node links to: a called function, the function being shown, or a constant that is the
    address of a function in ``kb``.
    """
    if isinstance(node, FunctionCallNode):
        callee = getattr(node, "callee_func", None)
        addr = getattr(callee, "addr", None)
        return addr if isinstance(addr, int) else None
    if isinstance(node, FunctionNode):
        addr = getattr(node, "addr", None)
        return addr if isinstance(addr, int) else None
    if isinstance(node, ConstantNode) and kb is not None:
        value = getattr(node, "value", None)
        if isinstance(value, int) and not isinstance(value, bool) and value in kb.functions:
            return value
    return None


__all__ = [
    "LINK_PREFIX",
    "LINK_TIER",
    "angr_url",
    "code_link_addr",
    "disasm_link_addr",
    "link_key",
    "split_link",
    "with_link",
]
