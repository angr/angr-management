"""
Which colour a disassembly instruction, block or edge gets, as a style key.

The functions here decide in the order the Qt frontend always has; each frontend turns the answer into its own colour.
An answer is a style key (a configuration entry name or one of the extra styles below), a colour object a plugin
returned, or None for "no background of its own".
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angrmanagement.utils.edge import EdgeSort

if TYPE_CHECKING:
    from collections.abc import Callable, Collection

    from angrmanagement.data.instance import Instance

#: The background of a patched instruction (Qt.darkYellow in the Qt frontend).
PATCHED_STYLE = "disasm.patched"
SELECTED_INSN_STYLE = "disasm_view_node_instruction_selected_background_color"
PATTERN_STYLE = "disasm_view_pattern_highlight_color"
BOOKMARK_STYLE = "disasm_view_bookmark_color"
BLOCK_STYLE = "disasm_view_node_background_color"
BLOCK_ZOOMED_OUT_STYLE = "disasm_view_node_zoomed_out_background_color"
BLOCK_BORDER_STYLE = "disasm_view_node_border_color"
BLOCK_SELECTED_BORDER_STYLE = "disasm_view_selected_node_border_color"

#: The colour entry of each kind of edge.
EDGE_COLORS = {
    EdgeSort.BACK_EDGE: "disasm_view_back_edge_color",
    EdgeSort.TRUE_BRANCH: "disasm_view_true_edge_color",
    EdgeSort.FALSE_BRANCH: "disasm_view_false_edge_color",
    EdgeSort.DIRECT_JUMP: "disasm_view_direct_jump_edge_color",
    EdgeSort.EXCEPTION_EDGE: "disasm_view_exception_edge_color",
}


def edge_style(sort: int | None) -> str:
    """The colour entry of an edge of ``sort`` (an EdgeSort value); direct jumps' for anything else."""
    return EDGE_COLORS.get(sort, EDGE_COLORS[EdgeSort.DIRECT_JUMP])  # type: ignore[arg-type]


def insn_background(
    addr: int,
    size: int,
    instance: Instance,
    selected: bool,
    pattern_addrs: Collection[int] = (),
    plugin_color: Callable[[int, bool], Any] | None = None,
) -> Any:
    """
    The background of the instruction at ``addr`` (``size`` bytes long).

    In order: a plugin's colour (``plugin_color(addr, selected)``; whatever it returns that is not None, as it is),
    the selection, a pattern highlight, a patch, a bookmark. None means no background: the block's shows.
    """
    if plugin_color is not None:
        color = plugin_color(addr, selected)
        if color is not None:
            return color

    if selected:
        return SELECTED_INSN_STYLE

    if addr in pattern_addrs:
        return PATTERN_STYLE

    patch_manager: Any = instance.patches
    if not patch_manager.am_none:
        patches = patch_manager.get_all_patches(addr, size)
        if len(patches):
            return PATCHED_STYLE

    if instance.annotations.has_bookmark(addr):
        return BOOKMARK_STYLE

    return None


def block_background(
    addr: int,
    should_omit_text: bool = False,
    color_override: Any = None,
    plugin_color: Callable[[int], Any] | None = None,
) -> Any:
    """
    The background of the graph block at ``addr``: an override set on the block, a plugin's colour
    (``plugin_color(addr)``), the zoomed-out colour when the text is not drawn, or the block colour.
    """
    if color_override is not None:
        return color_override

    if plugin_color is not None:
        color = plugin_color(addr)
        if color is not None:
            return color

    if should_omit_text:
        return BLOCK_ZOOMED_OUT_STYLE

    return BLOCK_STYLE


__all__ = [
    "BLOCK_BORDER_STYLE",
    "BLOCK_SELECTED_BORDER_STYLE",
    "BLOCK_STYLE",
    "BLOCK_ZOOMED_OUT_STYLE",
    "BOOKMARK_STYLE",
    "EDGE_COLORS",
    "PATCHED_STYLE",
    "PATTERN_STYLE",
    "SELECTED_INSN_STYLE",
    "block_background",
    "edge_style",
    "insn_background",
]
