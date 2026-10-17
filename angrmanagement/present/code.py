"""
The pseudocode view without a toolkit.

:class:`CodePresenter` holds what the pseudocode view shows and does: the function, the decompilation on screen
(``codegen``), the cursor's address and node, the jump history, the flavor, the decompilation options, the pattern
highlights, find, and every action of the view's keys and context menu. The frontend's view draws it and tells it
where the cursor is; it asks the view for the few things only a widget knows through methods the view may have
(``cursor_position``, ``selection_range``, ``set_cursor_position``, ...).

:class:`CodeDoc` is the decompilation as lines of :class:`~angrmanagement.present.spans.Span`, each styled as the Qt
highlighter styles it and owned by the node of the structured code under it. The functions at the top of the module
are the position-map helpers the Qt document used to have, and the text helpers of the rename and retype dialogs.
"""

from __future__ import annotations

import bisect
import contextlib
import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

import pycparser
from angr import SIM_TYPE_COLLECTIONS
from angr.ailment.expression import BinaryOp, Load, Op, UnaryOp
from angr.ailment.statement import Assignment, Store
from angr.analyses.decompiler.edits import (
    DecompilationEditError,
    resolve_variable,
    restore_user_edits,
)
from angr.analyses.decompiler.edits import rename_function as core_rename_function
from angr.analyses.decompiler.edits import rename_variable as core_rename_variable
from angr.analyses.decompiler.edits import set_function_prototype as core_set_function_prototype
from angr.analyses.decompiler.edits import set_variable_type as core_set_variable_type
from angr.analyses.decompiler.known_patterns.generator import PatternGenerationError, PatternGenerator
from angr.analyses.decompiler.optimization_passes.expr_op_swapper import OpDescriptor
from angr.analyses.decompiler.structured_codegen import (
    BinaryOpNode,
    ClosingObjectNode,
    ConstantNode,
    DummyStructuredCodeGenerator,
    ExpressionNode,
    FunctionCallNode,
    FunctionNode,
    IndexedVariableNode,
    LabelNode,
    StructFieldNode,
    UnaryOpNode,
    VariableFieldNode,
    VariableNode,
)
from angr.calling_conventions import SimRegArg, SimStackArg
from angr.errors import AngrMissingTypeError
from angr.knowledge_plugins.functions.function import Function
from angr.sim_type import NamedTypeMixin, SimType, SimTypePointer, TypeRef, parse_defns, parse_type
from angr.sim_variable import SimMemoryVariable, SimStackVariable, SimTemporaryVariable, SimVariable
from angr.utils.types import dereference_simtype, make_type_reference

from angrmanagement.config import Conf
from angrmanagement.data.jobs import DecompileFunctionJob, LLMPreloadCalleesJob, LLMRefineJob, VariableRecoveryJob
from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.commands import ViewCommand
from angrmanagement.logic.disassembly import JumpHistory
from angrmanagement.mcp.edit_hooks import WorkspaceEditHooks
from angrmanagement.utils import locate_function

from .base import FunctionPresenter, ask_text
from .code_highlight import highlight_runs, kind_style
from .code_options import DecompilationOptionsSheet
from .find import FindBarState
from .keymap import Binding, Keymap
from .menus import Menu, MenuEntry, MenuSeparator
from .spans import Doc, Line, Span

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal
    from angr.sim_type import SimTypeFunction

    from angrmanagement.data.instance import Instance

log = logging.getLogger(__name__)

#: The flavors the decompilation options apply to (the options pane shows only for these).
OPTION_FLAVORS = frozenset({"pseudocode", "rust", "go"})
#: The colours of the pseudocode text where nothing else styles it (the Qt editor's base and text colours).
CODE_BACKGROUND = "palette_text bg:palette_base"
#: The background of the text related to the node under the cursor.
CHUNK_STYLE = "bg:pseudocode_highlight_color"
#: The background of a find match (the disassembly's operand highlight, as the Qt view uses).
FIND_STYLE = "bg:disasm_view_operand_highlight_color"
#: The background of a line a pattern highlight covers.
PATTERN_LINE_STYLE = "bg:pseudocode_pattern_highlight_color"
#: The background of a bookmarked line.
BOOKMARK_LINE_STYLE = "bg:pseudocode_bookmark_color"
#: The background of the selection.
SELECTION_STYLE = "bg:palette_highlight"
#: What CodePresenter.context_menu takes as its node by default: the node under the cursor.
AT_CURSOR: Any = object()


#
# The position maps
#


def _codegen_of(codegen: Any) -> Any:
    """The codegen itself, from a codegen or an ObjectContainer of one; None when there is none."""
    if isinstance(codegen, ObjectContainer):
        return None if codegen.am_none else codegen.am_obj
    return codegen


def node_at_position(codegen: Any, pos: int) -> Any:
    """The node at text position ``pos``, or at the character before it (a cursor sits between characters)."""
    codegen = _codegen_of(codegen)
    if codegen is None or codegen.map_pos_to_node is None:
        return None
    node = codegen.map_pos_to_node.get_node(pos)
    if node is None:
        node = codegen.map_pos_to_node.get_node(pos - 1)
    return node


def _is_newline_or_out_of_bounds(text: str, pos: int) -> bool:
    if pos >= len(text):
        return True
    return text[pos] == "\n"


def stmt_node_at_position(codegen: Any, pos: int) -> Any:
    """
    The node with an address at ``pos``, or the nearest one on the same line, looking left and right in turn until a
    newline or the end of the text. A position past the end is moved back onto the text.
    """
    codegen = _codegen_of(codegen)
    if codegen is None or codegen.map_pos_to_addr is None:
        return None
    text = codegen.text
    node = codegen.map_pos_to_addr.get_node(pos)
    if node is not None:
        return node
    left = len(text) - 4 if pos >= len(text) - 2 else pos - 1
    right = pos + 1
    go_left = not _is_newline_or_out_of_bounds(text, left)
    go_right = not _is_newline_or_out_of_bounds(text, right)
    while go_left or go_right:
        if go_left:
            node = codegen.map_pos_to_addr.get_node(left)
            if node is not None:
                break
            left -= 1
            go_left = not _is_newline_or_out_of_bounds(text, left)
        if go_right:
            node = codegen.map_pos_to_addr.get_node(right)
            if node is not None:
                break
            right += 1
            go_right = not _is_newline_or_out_of_bounds(text, right)
    return node


def closest_node_pos(codegen: Any, ins_addr: int) -> int | None:
    """The text position of the statement nearest to the instruction at ``ins_addr``."""
    codegen = _codegen_of(codegen)
    if codegen is None:
        return None
    return codegen.map_addr_to_pos.get_nearest_pos(ins_addr)


def related_text_chunks(codegen: Any, node: Any) -> list[tuple[int, int]] | None:
    """The ``(start, end)`` text ranges of every mention of what ``node`` names: the variable, the constant, ..."""
    codegen = _codegen_of(codegen)
    if codegen is None or codegen.map_ast_to_pos is None:
        return None
    if isinstance(node, ConstantNode):
        key: Any = getattr(node, "value", None)
    elif isinstance(node, VariableNode):
        unified = getattr(node, "unified_variable", None)
        key = unified if unified is not None else getattr(node, "variable", None)
    elif isinstance(node, FunctionCallNode):
        callee = getattr(node, "callee_func", None)
        key = callee if callee is not None else getattr(node, "callee_target", None)
    elif isinstance(node, StructFieldNode):
        key = (getattr(node, "struct_type", None), getattr(node, "offset", None))
    elif isinstance(node, ClosingObjectNode | FunctionNode | SimType | LabelNode):
        key = node
    else:
        return []
    starts = codegen.map_ast_to_pos.get(key, None)
    if starts is None:
        return []
    chunks = []
    for start in starts:
        elem = codegen.map_pos_to_node.get_element(start)
        if elem is None:
            continue
        chunks.append((elem.start, elem.length + elem.start))
    return chunks


def snap_comment_addr(codegen, addr: int) -> int:
    """
    Pick the key under which a statement comment for ``addr`` actually renders inline.

    ``stmt_comments`` is consumed when a line ends, keyed by the *last* address-tagged construct on
    that line, so a key that is merely the nearest rendered address is often not enough: it ends up
    in the decompiler's "Orphaned comments" block instead. Map ``addr`` onto the line that renders
    it, then take the last address on that line.
    """
    addr_to_pos = getattr(codegen, "map_addr_to_pos", None)
    pos_to_addr = getattr(codegen, "map_pos_to_addr", None)
    text = getattr(codegen, "text", None)
    if addr_to_pos is None or pos_to_addr is None or not text:
        return addr

    # not codegen.map_addr_to_pos.get_nearest_pos(): it gives up when the address is outside the
    # rendered range, which is exactly the common case for a prologue instruction
    entries = [(ins_addr, elem.posmap_pos) for ins_addr, elem in addr_to_pos.items()]
    if not entries:
        return addr
    below = [e for e in entries if e[0] <= addr]
    pos = below[-1][1] if below else entries[0][1]

    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    if line_end == -1:
        line_end = len(text)

    posmap = pos_to_addr._posmap
    last = None
    for key in posmap.irange(minimum=line_start, maximum=line_end):
        tags = getattr(posmap[key].obj, "tags", None) or {}
        ins_addr = tags.get("ins_addr")
        if isinstance(ins_addr, int):
            last = ins_addr
    return addr if last is None else last


def floor_comment_addr(codegen, addr: int) -> int:
    """The key angr's own edit layer would have used. Only needed to recognize its writes."""
    insmap = getattr(codegen, "map_addr_to_pos", None)
    if insmap is None:
        return addr
    rendered = [ins_addr for ins_addr, _ in insmap.items()]
    if not rendered or addr in set(rendered):
        return addr
    below = [a for a in rendered if a < addr]
    return max(below) if below else addr


#
# Text helpers of the rename and retype dialogs
#


def is_valid_node_name(name: str) -> bool:
    """Whether ``name`` can name a node: not blank and without spaces once stripped."""
    stripped = name.strip()
    return bool(stripped) and " " not in stripped


def rename_default(node: Any) -> str:
    """The name the rename dialog starts with for ``node``."""
    if isinstance(node, VariableNode):
        unified = getattr(node, "unified_variable", None)
        if unified and unified.name:
            return unified.name
        variable = getattr(node, "variable", None)
        if variable is not None and not variable.region:
            return variable.name or ""
    elif isinstance(node, FunctionNode) and getattr(node, "name", None):
        return node.name  # type: ignore[attr-defined]
    elif isinstance(node, FunctionCallNode):
        callee = getattr(node, "callee_func", None)
        return callee.name if callee is not None else ""
    elif isinstance(node, StructFieldNode):
        return getattr(node, "field", "") or ""
    return ""


def rename_suggestions(node: Any) -> list[str]:
    """The names the rename dialog suggests for ``node``: its variable's candidate names."""
    if not isinstance(node, VariableNode):
        return []
    unified = getattr(node, "unified_variable", None)
    if unified is None or not unified.candidate_names:
        return []
    return list(unified.candidate_names)


def type_text(type_: SimType | None, cvariable: Any = None) -> str:
    """A type as the retype dialog shows it: a declaration of the variable, or of ``foobar``."""
    if type_ is None:
        return ""
    unified: Any = getattr(cvariable, "unified_variable", None) if cvariable is not None else None
    if isinstance(unified, SimVariable):
        return type_.c_repr(name=unified.name)
    return type_.c_repr(name="foobar")


def retype_default(node: Any, node_type: SimType | None) -> str:
    """The text the retype dialog starts with for ``node``."""
    if isinstance(node, VariableNode) and getattr(node, "unified_variable", None) and node_type is not None:
        return type_text(node_type, cvariable=node)
    if isinstance(node, FunctionNode):
        functy = getattr(node, "functy", None)
        if functy is not None:
            return functy.c_repr(name=getattr(node, "demangled_name", None), full=True, name_parens=False)
    return ""


def parse_type_text(type_str: str, predefined_types: dict | None = None) -> tuple[bool, str, SimType | None]:
    """
    Parse what the user typed as a type: a variable declaration such as ``char var``, or a type such as ``char``.
    Returns whether it is valid, why not, and the type.
    """
    declaration = type_str
    if not declaration.endswith(";"):
        declaration += ";"
    try:
        defns = parse_defns(declaration, predefined_types=predefined_types)
    except pycparser.c_parser.ParseError:
        defns = {}
    if len(defns) == 1:
        return True, "", next(iter(defns.values()))

    try:
        parsed_type = parse_type(type_str, predefined_types=predefined_types)
    except pycparser.c_parser.ParseError:
        return False, "Invalid type declaration string", None

    # once the type is parsed, try to convert it into a type reference and see if it resolves
    ref_type = make_type_reference(parsed_type)
    try:
        deref_type = dereference_simtype(ref_type, list(SIM_TYPE_COLLECTIONS.values()))
        return True, "", deref_type
    except AngrMissingTypeError as ex:
        return False, f"Unknown type {ex.missing_type}", None


def format_prototype(node: Any) -> str | None:
    """The prototype of the function a call node calls, with each argument's location: the hover text of a call."""
    if not isinstance(node, FunctionCallNode):
        return None
    func = getattr(node, "callee_func", None)
    if func is None or func.prototype is None:
        return None

    proto: SimTypeFunction = func.prototype
    name = func.demangled_name or func.name or "sub"
    ret = proto.returnty.c_repr() if proto.returnty else "void"

    parts = []
    args = proto.args or ()
    arg_names = proto.arg_names or ()

    arg_locs = None
    cc = func.calling_convention
    if cc is not None and args:
        arg_locs = cc.arg_locs(proto)

    for i, arg_type in enumerate(args):
        arg_name = arg_names[i] if i < len(arg_names) and arg_names[i] else f"a{i}"
        arg_str = f"{arg_type.c_repr()} {arg_name}"
        if arg_locs is not None and i < len(arg_locs):
            loc = arg_locs[i]
            if isinstance(loc, SimRegArg):
                arg_str += f" @ <{loc.reg_name}>"
            elif isinstance(loc, SimStackArg):
                arg_str += f" @ <stack+{loc.stack_offset:#x}>"
        parts.append(arg_str)

    if proto.variadic:
        parts.append("...")

    return f"{ret} {name}({', '.join(parts)})"


def rename_node_directly(workspace, instance, codegen, node: Any, node_name: str, func: Any = None) -> bool:
    """
    Rename ``node`` the way the rename dialog did before the edit layer: by changing the objects themselves. Returns
    whether there was something to rename. The caller re-renders.
    """
    code_kb = codegen.kb
    cfunc = codegen.cfunc
    if cfunc is None:
        return False
    obj: Any = node

    if isinstance(node, VariableNode) and getattr(node, "unified_variable", None) is not None:
        variable: Any = getattr(node, "variable", None)
        unified: Any = getattr(node, "unified_variable", None)
        if hasattr(variable, "offset") and variable.offset is not None:
            # a stack variable
            workspace.plugins.handle_stack_var_renamed(func, variable.offset, variable.name, node_name)
        elif unified.is_function_argument:
            workspace.plugins.handle_func_arg_renamed(code_kb.functions[cfunc.addr], 0, variable.name, node_name)
            arg_names = list(cfunc.functy.arg_names)
            for idx, arg in enumerate(cfunc.arg_list):
                if arg is node:
                    arg_names[idx] = node_name
                    break
            cfunc.functy.arg_names = tuple(arg_names)
        unified.name = node_name
        unified.renamed = True
    elif isinstance(node, VariableNode) and not obj.variable.region:
        # a global variable
        variable = obj.variable
        workspace.plugins.handle_global_var_renamed(variable.addr, variable.name, node_name)
        instance.kb.labels[variable.addr] = node_name
        variable.name = node_name
        variable.renamed = True
    elif isinstance(node, FunctionNode):
        fnode: Any = node
        workspace.plugins.handle_function_renamed(code_kb.functions[cfunc.addr], fnode.name, node_name)
        code_kb.functions.get_by_addr(fnode.addr).name = node_name
        fnode.name = node_name
        fnode.demangled_name = node_name
        workspace.on_function_updated()
    elif isinstance(node, FunctionCallNode):
        callee = getattr(node, "callee_func", None)
        if callee is not None:
            workspace.plugins.handle_function_renamed(code_kb.functions[cfunc.addr], callee.name, node_name)
            callee.name = node_name
            workspace.on_function_updated()
    elif isinstance(node, StructFieldNode):
        snode: Any = node
        fields = [(node_name if n == snode.field else n, t) for n, t in snode.struct_type.fields.items()]
        snode.struct_type.fields = OrderedDict(fields)
        workspace.plugins.handle_struct_changed(snode.field, node_name)
        snode.field = node_name
    elif isinstance(node, SimType):
        rename_type(node, node_name)
    else:
        return False
    return True


def rename_type(type_: SimType, name: str) -> None:
    """Rename a type, looking through type references and pointers; a reference is renamed with what it names."""
    target: Any = type_
    ref = None
    while True:
        if isinstance(target, TypeRef):
            ref = target
            target = target.type
        elif isinstance(target, SimTypePointer):
            ref = None
            target = target.pts_to
        else:
            break
    if isinstance(target, NamedTypeMixin):
        target.name = name
        if ref is not None:
            ref._name = name
    else:
        target.label = name


#
# The render model
#


@dataclass
class CodeDoc(Doc):
    """The decompiled text as lines of spans, with where each line starts in the text."""

    line_starts: list[int] = field(default_factory=list)
    text_length: int = 0

    def position(self, row: int, column: int) -> int:
        """The text position of ``(row, column)``, clamped to the line and the text."""
        if not self.lines:
            return 0
        row = max(0, min(row, len(self.lines) - 1))
        column = max(0, min(column, self.lines[row].width))
        return self.line_starts[row] + column

    def row_column(self, pos: int) -> tuple[int, int]:
        """The ``(row, column)`` of text position ``pos``."""
        if not self.lines:
            return 0, 0
        pos = max(0, min(pos, self.text_length))
        row = bisect.bisect_right(self.line_starts, pos) - 1
        return row, pos - self.line_starts[row]


def build_code_doc(codegen: Any, flavor: str | None = None, conf: Any = None) -> CodeDoc:
    """
    The text of ``codegen`` as a :class:`CodeDoc`: one line per line of text, a span per run of characters with the
    same style and the same node, styled as the Qt highlighter styles them.
    """
    codegen = _codegen_of(codegen)
    text = codegen.text if codegen is not None and codegen.text else ""
    posmap = getattr(codegen, "map_pos_to_node", None) if codegen is not None else None
    owners: list[Any] = [None] * len(text)
    if posmap is not None:
        for elem in posmap.values():
            for idx in range(max(elem.start, 0), min(elem.start + elem.length, len(text))):
                owners[idx] = elem.obj
    styles: dict[str | None, str] = {}

    def style_of(kind: str | None) -> str:
        if kind not in styles:
            styles[kind] = kind_style(kind, conf)
        return styles[kind]

    doc = CodeDoc(text_length=len(text))
    in_comment = False
    start = 0
    for row_text in text.split("\n"):
        runs, in_comment = highlight_runs(row_text, start, posmap, flavor, in_comment)
        kinds: list[str | None] = [None] * len(row_text)
        for run_start, count, kind in runs:
            for idx in range(run_start, run_start + count):
                kinds[idx] = kind
        line = Line()
        col = 0
        while col < len(row_text):
            kind, owner = kinds[col], owners[start + col]
            end = col + 1
            while end < len(row_text) and kinds[end] == kind and owners[start + end] is owner:
                end += 1
            line.spans.append(Span(row_text[col:end], style_of(kind), owner))
            col = end
        doc.lines.append(line)
        doc.line_starts.append(start)
        start += len(row_text) + 1
    return doc


#
# Keys and commands
#

#: The pseudocode view's palette commands: caption and the presenter method each runs (CodeView.register_commands).
CODE_COMMANDS: list[tuple[str, str]] = [
    ("Find", "show_find_bar"),
    ("Find Next", "find_next"),
    ("Find Previous", "find_previous"),
]


def pseudocode_keymap() -> Keymap:
    """
    The pseudocode view's keys: CodeView.keyPressEvent, the shortcuts of QCCodeEdit's context menu and its
    keyPressEvent, and the find shortcuts. The terminal adds Shift+F10 for the context menu, Enter for what a double
    click does, and Alt+Left/Right for the Nav tool bar's back and forward.
    """
    return Keymap(
        "pseudocode",
        [
            Binding("Tab", "go_to_disassembly", "Show the cursor's address in the disassembly"),
            Binding("G", "popup_jumpto_dialog", "Jump to an address or a function"),
            Binding("Esc", "escape", "Clear the pattern highlights, or jump back"),
            Binding("Space", "next_flavor", "Show the next flavor of the decompilation"),
            Binding("N", "rename_node", "Rename"),
            Binding("X", "xref_node", "Cross-references"),
            Binding("Y", "retype_node", "Specify a new type"),
            Binding("H", "hex_constant", "Toggle hex"),
            Binding("_", "neg_constant", "Toggle negative"),
            Binding("R", "char_constant", "Toggle char"),
            Binding(";", "comment", "Comment"),
            Binding("/", "comment", "Comment"),
            Binding("?", "comment_expr", "Expression comment"),
            Binding(":", "comment_multiline", "Comment (multi-line)"),
            Binding("Ctrl+F", "show_find_bar", "Find"),
            Binding("F3", "find_next", "Find next"),
            Binding("Shift+F3", "find_previous", "Find previous", 2, "Shift+N"),
            Binding("Ctrl+=", "zoom_in", "Zoom in"),
            Binding("Ctrl+-", "zoom_out", "Zoom out"),
            Binding("Shift+F10", "context_menu", "Context menu"),
            Binding("Return", "activate", "Follow the node under the cursor (a double click)"),
            Binding("Alt+Left", "jump_back", "Jump back", 2, "Ctrl+Left"),
            Binding("Alt+Right", "jump_forward", "Jump forward", 2, "Ctrl+Right"),
        ],
    )


def register_code_commands(workspace, view_class: type | None = None) -> None:
    """Register the pseudocode view's palette commands; they run on the focused view's presenter."""
    if view_class is None:
        view_class = CodePresenter
    workspace.command_manager.register_commands(
        [
            ViewCommand(
                "code_view_" + method, "Pseudocode: " + caption, getattr(view_class, method), view_class, workspace
            )
            for caption, method in CODE_COMMANDS
        ]
    )


#: The context menu entries: the key of each (QCCodeEdit's QAction attribute), its caption and its shortcut.
MENU_ACTIONS: dict[str, tuple[str, str | None, str]] = {
    "action_rename_node": ("Rename...", "N", "rename_node"),
    "action_xref": ("Xrefs...", "X", "xref_node"),
    "action_retype_node": ("Specify a new type", "Y", "retype_node"),
    "action_toggle_struct": ("Toggle &struct/array", None, "toggle_struct"),
    "action_collapse_expr": ("Collapse expression", None, "collapse_expr"),
    "action_expand_expr": ("Expand expression", None, "expand_expr"),
    "action_hex": ("Toggle hex", "H", "hex_constant"),
    "action_neg": ("Toggle negative", "_", "neg_constant"),
    "action_char": ("Toggle char", "R", "char_constant"),
    "action_float": ("Toggle float", None, "float_constant"),
    "action_double": ("Toggle double", None, "double_constant"),
    "action_to_ite_expr": ("Create a ternary expression", None, "convert_to_ite_expr"),
    "action_swap_binop_operands": ("Swap operands", None, "swap_binop_operands"),
    "action_comment": ("Comment...", ";", "comment"),
    "action_pattern": ("Create pattern from selection...", None, "create_pattern"),
    "action_asmgen": ("Expression -> ARM THUMB assembly...", None, "expr2armasm"),
    "action_copy": ("Copy", "Ctrl+C", "copy"),
    "action_select_all": ("Select all", "Ctrl+A", "select_all"),
    "action_llm_refine_all": ("AI: Refine All", None, "llm_refine_all"),
    "action_llm_suggest_var_names": ("AI: Suggest Variable Names", None, "llm_suggest_var_names"),
    "action_llm_suggest_func_name": ("AI: Suggest Function Name", None, "llm_suggest_func_name"),
    "action_llm_suggest_var_types": ("AI: Suggest Variable Types", None, "llm_suggest_var_types"),
    "action_clear_pattern_highlights": ("Clear pattern highlights", None, "clear_pattern_highlight"),
}

#: The separators of the menu: the one before Copy (shared by every group, as the Qt menu's) and the AI one.
BASE_SEPARATOR = "separator_base"
LLM_SEPARATOR = "separator_llm"

_COMMENT_KEYS = ["action_comment", "action_pattern"]
_BASE_KEYS = [BASE_SEPARATOR, "action_copy", "action_select_all"]
_EXPR_KEYS = ["action_to_ite_expr", "action_swap_binop_operands", "action_collapse_expr", "action_expand_expr"]
_LLM_KEYS = [
    LLM_SEPARATOR,
    "action_llm_refine_all",
    "action_llm_suggest_var_names",
    "action_llm_suggest_func_name",
    "action_llm_suggest_var_types",
]


def _add_keys(keys: list[str], more: Iterable[str]) -> None:
    """Add ``more`` to ``keys`` as QWidget.addAction adds actions: one already there moves to the end."""
    for key in more:
        if key in keys:
            keys.remove(key)
        keys.append(key)


def context_menu_keys(node: Any) -> list[str]:
    """
    The QCCodeEdit actions the context menu shows for ``node``, in order (QCCodeEdit.get_context_menu): each kind of
    node adds its group, and an action a later group adds again moves to the end, as it does on a QMenu.
    """
    keys: list[str] = []
    if isinstance(node, ConstantNode):
        _add_keys(
            keys,
            ["action_hex", "action_neg", "action_char", "action_float", "action_double"]
            + _COMMENT_KEYS
            + _BASE_KEYS
            + _EXPR_KEYS,
        )
    if isinstance(node, BinaryOpNode | UnaryOpNode):
        _add_keys(keys, _COMMENT_KEYS + _BASE_KEYS + _EXPR_KEYS)
    tags = getattr(node, "tags", None) or {}
    if isinstance(node, FunctionCallNode) and "vex_block_addr" in tags and "ins_addr" in tags:
        _add_keys(keys, ["action_rename_node", "action_xref"] + _COMMENT_KEYS + _BASE_KEYS + _EXPR_KEYS)
    if isinstance(node, VariableNode | IndexedVariableNode | VariableFieldNode | StructFieldNode):
        _add_keys(
            keys,
            ["action_rename_node", "action_retype_node", "action_toggle_struct", "action_asmgen", "action_xref"]
            + _COMMENT_KEYS
            + _BASE_KEYS
            + _EXPR_KEYS,
        )
    if isinstance(node, FunctionNode):
        _add_keys(keys, ["action_rename_node", "action_xref", "action_retype_node"] + _COMMENT_KEYS + _BASE_KEYS)
    else:
        _add_keys(keys, _COMMENT_KEYS + _BASE_KEYS)
    return keys


def selects_node(node: Any) -> bool:
    """Whether the context menu acts on ``node`` (the node kinds that have their own group of entries)."""
    tags = getattr(node, "tags", None) or {}
    return isinstance(
        node,
        ConstantNode
        | BinaryOpNode
        | UnaryOpNode
        | VariableNode
        | IndexedVariableNode
        | VariableFieldNode
        | StructFieldNode
        | FunctionNode,
    ) or (isinstance(node, FunctionCallNode) and "vex_block_addr" in tags and "ins_addr" in tags)


#
# The presenter
#


class CodePresenter(FunctionPresenter):
    """
    The state and actions of the pseudocode view. Watch and change its four ObjectContainers: ``addr``,
    ``current_node``, ``codegen`` and ``function``.

    The view the presenter is shown in (``self.view``) may answer: ``cursor_position()``, ``selection_range()``,
    ``selected_text()``, ``plain_text()``, ``set_cursor_position(pos)``, ``select_range(start, end)``,
    ``focus_text()``, ``on_flavors_changed()``, ``on_chunks_changed()``, ``on_pattern_highlight_changed()``,
    ``on_pattern_highlight_cleared()``, ``reload_patterns()``, ``on_find_matches_changed()``, ``find_bar_opened()``,
    ``find_bar_closed()``, ``close_view_requested()``, ``copy()``, ``select_all()``, and the asks ``ask_rename``,
    ``ask_type``, ``ask_comment``, ``ask_expr_comment`` and ``ask_pattern_name``. A view without them gets the
    presenter's defaults.
    """

    # the knowledge base, the codegen and the nodes are angr's untyped objects
    instance: Any
    codegen: Any
    addr: Any
    current_node: Any
    _function: Any

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "pseudocode", instance, default_docking_position)
        self.base_caption = "Pseudocode"
        self._function.am_name = "The function to decompile"
        self.current_node = ObjectContainer(None, "Current selected C-code node")
        self.addr = ObjectContainer(0, "Current cursor address")
        self.codegen = ObjectContainer(None, "The currently-displayed codegen object")

        self.last_function: Function | None = None
        self.jump_history = JumpHistory()
        self.vars_must_struct: set[str] = set()
        #: the flavors of the function's decompilations, as the flavor selector lists them
        self.available_flavors: list[str] = []
        # the Qt view gives its options widget; any other view gets a sheet, made when first asked for
        self._options: Any = None
        #: the find bar the view shows (a FindBarState or the Qt QFindBar)
        self.find_bar: Any = None
        self.find_matches: list[tuple[int, int]] = []
        self.find_index = -1
        #: the text ranges of the node under the cursor and its other mentions
        self.chunks: list[tuple[int, int]] = []
        #: the node the last context menu was built for
        self.selected_node: Any = None
        #: whether the view shows a document of the codegen (the Qt view sets it when it makes its document)
        self.rendered = False
        #: the decompilation as spans, for frontends that draw spans (built by build_doc)
        self.doc: CodeDoc | None = None
        #: layer name -> (function address, instruction addresses of each highlighted copy);
        #: kept as addresses so a highlight survives the pseudocode being regenerated
        self.highlight_layers: dict[str, tuple[int, list[frozenset[int]]]] = {}
        #: patterns whose outlined calls are highlighted in whatever function is shown
        self.highlighted_patterns: set[str] = set()
        # kb.comments mirrored into the current codegen's stmt_comments: kb address -> stmt key
        self.mirrored_codegen = None
        self.mirrored_comments: dict[int, int] = {}

    @property
    def options(self) -> Any:
        """What the decompilations are given: the Qt view's options widget, or a DecompilationOptionsSheet."""
        if self._options is None:
            self._options = DecompilationOptionsSheet(self.instance, self._plugin_passes)
        return self._options

    @options.setter
    def options(self, value: Any) -> None:
        self._options = value

    def _plugin_passes(self) -> list:
        plugins = getattr(self.workspace, "plugins", None)
        return list(plugins.optimization_passes()) if plugins is not None else []

    #
    # What the view answers
    #

    def _view_attr(self, name: str) -> Callable | None:
        if self.view is None or self.view is self:
            return None
        return getattr(self.view, name, None)

    def _view_call(self, name: str, *args, **kwargs) -> Any:
        func = self._view_attr(name)
        return func(*args, **kwargs) if func is not None else None

    def view_or_self(self, name: str) -> Callable:
        """The view's ``name`` if it has one (what the Qt view and the tests replace), else the presenter's."""
        return self._view_attr(name) or getattr(self, name)

    def cursor_position(self) -> int:
        pos = self._view_call("cursor_position")
        return pos if isinstance(pos, int) else 0

    def selection_range(self) -> tuple[int, int]:
        """The selection's ``(start, end)``; equal when nothing is selected."""
        rng = self._view_call("selection_range")
        if rng is None:
            pos = self.cursor_position()
            return pos, pos
        return rng

    def plain_text(self) -> str:
        """The text the view shows: the codegen's, unless the view says otherwise."""
        text = self._view_call("plain_text")
        if isinstance(text, str):
            return text
        return "" if self.codegen.am_none else self.codegen.text or ""

    #
    # Properties
    #

    @property
    def flavor(self) -> str | None:
        """The flavor of the codegen shown."""
        return self.codegen.flavor if not self.codegen.am_none else None

    @property
    def best_flavor(self) -> str:
        if self.instance.project.am_none:
            return "pseudocode"
        if self.instance.project.is_rust_binary:
            return "rust"
        if self.instance.project.is_go_binary:
            return "go"
        return "pseudocode"

    @property
    def kb(self) -> Any:
        return self.instance.kb

    @property
    def keymap(self) -> Keymap:
        return pseudocode_keymap()

    def commands(self) -> list:
        return [cmd for cmd in self.workspace.command_manager.get_commands() if cmd.name.startswith("code_view_")]

    def build_doc(self, conf: Any = None) -> CodeDoc | None:
        """Make :attr:`doc` from the codegen shown (None when there is none) and return it."""
        self.doc = None if self.codegen.am_none else build_code_doc(self.codegen.am_obj, self.flavor, conf)
        return self.doc

    #
    # Reloading and decompiling
    #

    def reload(self) -> None:
        if self.instance.project.am_none:
            return
        self.options.reload(force=True)
        self.vars_must_struct = set()

    def decompile(
        self,
        clear_prototype: bool = False,
        focus: bool = False,
        focus_addr=None,
        flavor: str | None = None,
        reset_cache: bool = False,
        regen_clinic: bool = True,
        on_finish: Callable[[], None] | None = None,
    ) -> None:
        function: Any = self._function
        if function.am_none:
            return

        if flavor is None:
            flavor = self.best_flavor if self.codegen.am_none else self.codegen.flavor

        if clear_prototype:
            # clear the existing function prototype
            function.prototype = None
            function.ran_cca = False

        if reset_cache:
            self.kb.decompilations.discard((function.addr, flavor))
            variables = self.kb.dec_variables
            if variables.has_function_manager(function.addr):
                del variables[function.addr]

        def decomp_ready(*args, **kwargs) -> None:  # pylint:disable=unused-argument
            # this code is _partially_ duplicated from on_new_function. be careful!
            self.set_available_flavors(self.kb.decompilations.all_flavors(function.addr))
            available = self.kb.decompilations.available_flavors(function.addr)
            if available:
                chosen_flavor = flavor if flavor in available else available[0]
                cached = self.kb.decompilations[(function.addr, chosen_flavor)]
                if cached is not None:
                    self.codegen.am_obj = cached.codegen
                    self.codegen.am_event(already_regenerated=True)
                    self.focus_core(focus, focus_addr)
                    if focus_addr is not None:
                        self.jump_history.record_address(focus_addr)
                    else:
                        self.jump_history.record_address(function.am_obj.addr)
                    self.last_function = function.am_obj
            self.maybe_preload_callees()
            self.maybe_auto_llm_refine()
            if on_finish is not None:
                on_finish()

        def decomp(*_) -> None:
            job = DecompileFunctionJob(
                self.instance,
                function.am_obj,
                cfg=self.instance.cfg,
                options=self.options.option_and_values,
                optimization_passes=self.options.selected_passes,
                peephole_optimizations=self.options.selected_peephole_opts,
                inline_functions=self.instance.functions_to_inline,
                vars_must_struct=self.vars_must_struct,
                on_finish=decomp_ready,
                blocking=True,
                regen_clinic=regen_clinic,
                flavor=flavor,
            )
            self.workspace.job_manager.add_job(job)

        if function.ran_cca is False and (function.prototype is None or function.is_prototype_guessed is True):
            # run calling convention analysis for this function
            if self.instance.analysis_configuration:
                options = self.instance.analysis_configuration["varec"].to_dict()
            else:
                options = {}
            options["workers"] = 0
            varrec_job = VariableRecoveryJob(self.instance, **options, on_finish=decomp, func_addr=function.addr)
            self.workspace.job_manager.add_job(varrec_job)
        else:
            decomp()

    def apply_options(self) -> None:
        """
        Use the options as they are now (the options pane's Apply): decompile again if a change needs it, otherwise
        render the decompilation again with the new values.
        """
        if self.options.dirty:
            self.options.dirty = False
            self.view_or_self("decompile")(reset_cache=True)
        elif not self.codegen.am_none:
            self.codegen.reapply_options(self.options.option_and_values)
            self.codegen.am_event()

    def maybe_auto_llm_refine(self) -> None:
        """Dispatch LLM refinement jobs for any auto-* options that are enabled."""
        if self._function.am_none or self.instance.project.am_none:
            return
        if self.instance.project.am_obj.llm_client is None:
            return

        func = self._function.am_obj
        codegen = self.codegen

        def on_finish(*_args, **_kwargs):
            codegen.am_event(already_regenerated=True)

        modes: list[str] = []
        if Conf.llm_auto_rename_variables:
            modes.append(LLMRefineJob.SUGGEST_VARIABLE_NAMES)
        if Conf.llm_auto_rename_function:
            modes.append(LLMRefineJob.SUGGEST_FUNCTION_NAME)
        if Conf.llm_auto_retype_variables:
            modes.append(LLMRefineJob.SUGGEST_VARIABLE_TYPES)
        if Conf.llm_auto_summarize:
            modes.append(LLMRefineJob.SUMMARIZE)

        for mode in modes:
            job = LLMRefineJob(self.instance, func, mode=mode, on_finish=on_finish)
            self.workspace.job_manager.add_job(job)

    def maybe_preload_callees(self) -> None:
        if not Conf.llm_preload_callees:
            return
        if self._function.am_none or self.instance.project.am_none:
            return
        if self.instance.project.am_obj.llm_client is None:
            return
        job = LLMPreloadCalleesJob(self.instance, self._function.am_obj)
        self.workspace.job_manager.add_job(job)

    def function_summary(self) -> str | None:
        """The LLM's summary of the function from the decompilation cache, if it has one."""
        if self._function.am_none:
            return None
        key = (self._function.am_obj.addr, "pseudocode")
        if key in self.kb.decompilations:
            dec_cache = self.kb.decompilations[key]
            if dec_cache is not None and getattr(dec_cache, "function_summary", None):
                return dec_cache.function_summary
        return None

    @property
    def shows_options(self) -> bool:
        """Whether the decompilation options apply to the flavor shown."""
        return self.flavor in OPTION_FLAVORS

    #
    # The function, the codegen and the cursor
    #

    def set_available_flavors(self, flavors: Iterable[str]) -> None:
        self.available_flavors = list(flavors)
        self._view_call("on_flavors_changed")

    def focus_core(self, focus: bool, focus_addr: int | None) -> None:
        if focus:
            self.focus()
            self._view_call("focus_requested")
        if focus_addr is not None:
            self.addr.am_obj = focus_addr
            self.addr.am_event(focus=True)

    def on_new_function(self, focus: bool = False, focus_addr=None, flavor=None, **kwargs) -> None:  # pylint:disable=unused-argument
        """A new function was set: show its decompilation, decompiling it first if there is none."""
        function: Any = self._function
        if flavor is None:
            flavor = self.best_flavor if self.codegen.am_none else self.codegen.flavor

        if not self.codegen.am_none and self.last_function is function.am_obj:
            self.focus_core(focus, focus_addr)
            return
        self.set_available_flavors(self.kb.decompilations.all_flavors(function.addr))
        available = self.kb.decompilations.available_flavors(function.addr)
        should_decompile = True
        if available:
            chosen_flavor = flavor if flavor in available else available[0]
            dec = self.kb.decompilations[(function.addr, chosen_flavor)]
            cached = dec.codegen if dec is not None else None
            if cached is not None and not isinstance(cached, DummyStructuredCodeGenerator):
                should_decompile = False
                self.codegen.am_obj = cached
                self.codegen.am_event()
                self.focus_core(focus, focus_addr)
                self.last_function = function.am_obj

        self.jump_history.jump_to(function.addr)

        if should_decompile:
            self.view_or_self("decompile")(focus=focus, focus_addr=focus_addr, flavor=flavor)

        console_view = self.workspace.view_manager.first_view_in_category("console")
        if console_view is not None:
            console_view.set_current_function(function.am_obj)

    def function_at(self, addr: int) -> Function | None:
        """The function owning the block that contains ``addr``, or None if unknown."""
        if self.instance.cfb.am_none or self.instance.cfg.am_none:
            return None
        try:
            block_addr, _ = self.instance.cfb.floor_item(addr)
        except KeyError:
            return None
        block = self.instance.cfg.get_any_node(block_addr)
        if block is None or block.function_address not in self.kb.functions:
            return None
        return self.kb.functions[block.function_address]

    def on_new_addr(self, already_moved: bool = False, focus: bool = False, **kwargs) -> None:  # pylint:disable=unused-argument
        """The cursor address changed: show another function if it is in one, else move the cursor there."""
        if already_moved:
            return
        addr = self.addr.am_obj

        # the address may belong to another function (e.g., jumping back across a call); the nearest rendered
        # position is only meaningful within the current function
        func = self.function_at(addr)
        if func is not None and func is not self._function.am_obj:
            self._function.am_obj = func
            self._function.am_event(focus_addr=addr, focus=focus)
            return

        new_text_pos = closest_node_pos(self.codegen, addr) if self.rendered else None
        if new_text_pos is None:
            if func is not None:
                log.error("There is a block which is in the current function but find_closest_node_pos failed on it")
            return
        self._view_call("set_cursor_position", new_text_pos)
        if focus:
            self._view_call("focus_text")
            self.focus_core(True, None)

    def cursor_moved(self, pos: int | None = None) -> None:
        """The cursor moved to ``pos``: highlight what the node there names, and make it the current node."""
        if not self.rendered:
            return
        if pos is None:
            pos = self.cursor_position()
        selected_node = node_at_position(self.codegen, pos)
        if selected_node is not None:
            self.chunks = related_text_chunks(self.codegen, selected_node) or []
        else:
            self.chunks = []
        self._view_call("on_chunks_changed")
        self.current_node.am_obj = selected_node
        self.current_node.am_event()

    def on_new_node(self, **kwargs) -> None:  # pylint:disable=unused-argument
        """The current node changed: the cursor address follows it."""
        self.addr.am_obj = self.src_to_inst()
        self.addr.am_event(already_moved=True)

    def src_to_inst(self, pos: int | None = None) -> int:
        """The instruction address of the statement at ``pos`` (the cursor's), or the function's if there is none."""
        if pos is None:
            pos = self.cursor_position()
        current_node = stmt_node_at_position(self.codegen, pos)
        tags = getattr(current_node, "tags", None) if current_node is not None else None
        if tags is not None and "ins_addr" in tags:
            return tags["ins_addr"]
        return self._function.addr

    def closest_insaddr(self, node: Any, expr: bool = False, pos: int | None = None) -> int | None:
        """The instruction address of ``node``, or of the statement of the line the cursor is on."""
        addr = (getattr(node, "tags", None) or {}).get("ins_addr", None)
        if addr is not None:
            return addr
        if expr:
            return self.src_to_inst(pos)
        if pos is None:
            pos = self.cursor_position()
        text = self.plain_text()
        # find until the next newline, and use the location before it: otherwise we get the next line's node
        while pos < len(text) and text[pos] != "\n":
            pos += 1
        node = stmt_node_at_position(self.codegen, pos - 1)
        return (getattr(node, "tags", None) or {}).get("ins_addr", None)

    def variable_manager(self, func_addr: int | Literal["global"] | None = None) -> VariableManagerInternal | None:
        if self.codegen.am_none:
            return None
        if func_addr is None and not self._function.am_none:
            func_addr = self._function.addr
        if func_addr is None:
            return None
        variables = self.codegen.kb.dec_variables
        return variables[func_addr] if func_addr in variables else None  # noqa:SIM401

    def sync_kb_comments(self) -> bool:
        """
        Mirror ``kb.comments`` for this function into the codegen's statement comments so comments
        made in the disassembly (or before a re-decompilation) show up in the pseudocode. Returns
        whether anything changed, i.e. whether a re-render is needed.

        The function's entry address is skipped: the decompiler already renders that one as the
        function header, and mirroring it would render it a second time as an orphaned comment.
        """
        if self.codegen.am_none or self._function.am_none:
            return False
        kb = self.kb
        codegen = self.codegen.am_obj
        stmt_comments = getattr(codegen, "stmt_comments", None)
        if kb is None or stmt_comments is None:
            return False

        if self.mirrored_codegen is not codegen:
            self.mirrored_codegen = codegen
            self.mirrored_comments = {}

        func = self._function.am_obj
        low, high = func.addr, func.addr + max(func.size, 1)
        desired = {
            addr: text for addr, text in kb.comments.items() if text and addr != func.addr and low <= addr < high
        }

        changed = False
        for addr, key in list(self.mirrored_comments.items()):
            if addr not in desired:
                if key in stmt_comments:
                    del stmt_comments[key]
                    changed = True
                del self.mirrored_comments[addr]

        for addr, text in desired.items():
            key = self.mirrored_comments.get(addr)
            if key is None:
                # adopt an existing entry written by another path (e.g. the MCP edit tools) rather
                # than adding a second copy of the same comment
                floor = floor_comment_addr(codegen, addr)
                key = floor if stmt_comments.get(floor) == text else snap_comment_addr(codegen, addr)
                self.mirrored_comments[addr] = key
            if stmt_comments.get(key) != text:
                stmt_comments[key] = text
                changed = True
        return changed

    def regenerate_codegen(self, already_regenerated: bool = False, event: str | None = None, **kwargs) -> None:
        """
        Bring the codegen's text up to date after a change (the work of the codegen event, before the view shows it).

        :param already_regenerated: The text is current; only show it.
        :param event:               What changed: "retype_variable" re-flows the variable types, "retype_function"
                                    decompiles again (and puts ``user_edits`` back), anything else regenerates the
                                    text.
        """
        if not already_regenerated:
            update_var_types = False
            function: Any = self._function
            if event == "retype_variable":
                dec = self.instance.project.analyses.Decompiler(function.am_obj, decompile=False, use_cache=True)
                dec_cache = self.kb.decompilations[(function.addr, "pseudocode")]
                new_codegen = dec.reflow_variable_types(dec_cache)
                # update the cache
                dec_cache.codegen = new_codegen
                self.codegen.am_obj = new_codegen
                update_var_types = True
            elif event == "retype_function":
                # dropping the variable manager is what makes the new prototype take effect; it also drops every
                # rename and manual type, so put the snapshot back once the new variables exist
                user_edits = kwargs.get("user_edits") or {}

                def restore_edits() -> None:
                    if restore_user_edits(self.kb, function.addr, user_edits)[0]:
                        self.codegen.am_event()

                self.view_or_self("decompile")(reset_cache=True, on_finish=restore_edits if user_edits else None)
                update_var_types = True

            if not update_var_types:
                # regenerate text in the end
                self.codegen.regenerate_text()
            else:
                # trigger a full analysis
                self.codegen.cleanup()
                self.codegen._analyze()
        self.options.dirty = False

    #
    # Jumps
    #

    def jump_to(self, addr: int, src_ins_addr=None) -> bool:  # pylint:disable=unused-argument
        if addr == self.addr.am_obj:
            return False
        self.addr.am_obj = addr
        self.addr.am_event()
        return True

    def jump_back(self) -> None:
        addr = self.jump_history.backtrack()
        if addr is None:
            self._view_call("close_view_requested")
        else:
            self.view_or_self("jump_to")(addr)

    def jump_forward(self) -> None:
        addr = self.jump_history.forwardstep()
        if addr is not None:
            self.view_or_self("jump_to")(addr)

    def jump_to_history_position(self, pos: int) -> None:
        addr = self.jump_history.step_position(pos)
        if addr is not None:
            self.view_or_self("jump_to")(addr)

    def history_menu(self) -> Menu:
        """The jump history, newest first, as a menu of entries that go there (the Nav tool bar's drop-down)."""
        menu = Menu("&History")
        history = self.jump_history.history
        for pos in reversed(range(len(history))):
            addr = history[pos]
            func = locate_function(self.instance, addr) if not self.instance.project.am_none else None
            caption = f"{addr:#x}" if func is None else f"{func.name}+{addr - func.addr:#x} ({addr:#x})"
            menu.add(
                MenuEntry(
                    caption,
                    lambda _checked=True, p=pos: self.jump_to_history_position(p),
                    checkable=True,
                    checked=pos == self.jump_history.pos,
                )
            )
        return menu

    def navigate_to_function(self, from_addr: int, to_func: Function) -> None:
        self.jump_history.record_address(from_addr)
        self.jump_history.jump_to(to_func.addr)
        self.workspace.decompile_function(to_func, view=self.view if self.view is not None else self)

    def resolve_address(self, text: str) -> int | None:
        """An address from what the user typed: a number (hex with or without 0x), a function name or a label."""
        if self.instance.project.am_none:
            return None
        kb = self.kb
        with contextlib.suppress(KeyError):
            return kb.functions[text].addr
        for addr, name in kb.labels.items():
            if name == text:
                return addr
        with contextlib.suppress(ValueError):
            return int(text, 16)
        with contextlib.suppress(ValueError):
            return int(text, 0)
        return None

    def popup_jumpto_dialog(self) -> None:
        """Ask for an address or a function name and go there (the Qt view shows its JumpTo dialog instead)."""

        def then(answer: str | None) -> None:
            if not answer:
                return
            addr = self.resolve_address(answer.strip())
            if addr is None:
                GlobalInfo.ui_services.message("warning", "Jump to", f"Cannot find {answer!r}.")
                return
            self.view_or_self("jump_to")(addr)

        ask_text("Jump to", "Address or function name:", "", then)

    def disassembly_target_addr(self) -> int | None:
        """
        The address the disassembly view should show for the current cursor; falls back to the function head when the
        cursor address is unset or points outside the binary (e.g., a synthesized node tagged with address 0).
        """
        addr = self.addr.am_obj
        loader = self.instance.project.loader if not self.instance.project.am_none else None
        if isinstance(addr, int) and addr and (loader is None or loader.find_object_containing(addr) is not None):
            return addr
        return self._function.addr if not self._function.am_none else None

    def go_to_disassembly(self) -> None:
        """Tab: show the cursor's address in the disassembly view."""
        self.workspace.jump_to(self.disassembly_target_addr())

    def escape(self) -> None:
        """The first Escape dismisses a pattern highlight; with none shown it navigates back."""
        if not self.clear_pattern_highlight():
            self.jump_back()

    def activate(self, node: Any = None) -> None:
        """What a double click on ``node`` (the cursor's by default) does: follow the call, constant or variable."""
        if not self.rendered:
            return
        if node is None:
            node = node_at_position(self.codegen, self.cursor_position())
        if node is None:
            return
        tags = getattr(node, "tags", None) or {}
        if isinstance(node, FunctionCallNode):
            # decompile this new function
            callee = getattr(node, "callee_func", None)
            if callee is not None:
                self.navigate_to_function(tags["ins_addr"], callee)
        elif isinstance(node, ConstantNode):
            # jump to highlighted constants
            refs = getattr(node, "reference_values", None)
            value = getattr(node, "value", None)
            if refs is not None and value is not None:
                for ref in refs.values():
                    if isinstance(ref, Function):
                        self.navigate_to_function(tags["ins_addr"], ref)
                        return
                self.workspace.jump_to(value)
        elif isinstance(node, VariableNode):
            var = getattr(node, "variable", None)
            if var and isinstance(var, SimMemoryVariable):
                self.workspace.jump_to(var.addr)
        elif isinstance(node, LabelNode) and "ins_addr" in tags:
            self.workspace.jump_to(tags["ins_addr"])

    #
    # Flavors
    #

    def select_flavor(self, flavor: str) -> None:
        """Show the decompilation of ``flavor``, decompiling it first if there is none (the flavor selector)."""
        if self._function.am_none:
            return
        key = self._function.addr, flavor
        if key in self.kb.decompilations:
            # it's available; just switch
            self.codegen.am_obj = self.kb.decompilations[key].codegen
            self.codegen.am_event()
        else:
            self.view_or_self("decompile")(flavor=flavor)

    def next_flavor(self) -> None:
        """Space: show the next flavor of the decompilation."""
        if self.codegen.am_none:
            return
        flavor = self.codegen.flavor
        flavors = self.kb.decompilations.available_flavors(self._function.addr)
        idx = flavors.index(flavor)
        newidx = (idx + 1) % len(flavors)
        self.codegen.am_obj = self.kb.decompilations[(self._function.addr, flavors[newidx])].codegen
        self.codegen.am_event()

    def flavor_menu(self) -> Menu:
        """The flavors to pick from (the flavor selector's list)."""
        menu = Menu("&Flavor")
        for flavor in self.available_flavors:
            menu.add(
                MenuEntry(
                    flavor,
                    lambda _checked=True, f=flavor: self.select_flavor(f),
                    checkable=True,
                    checked=flavor == self.flavor,
                )
            )
        return menu

    #
    # Highlights
    #

    def highlight_pattern(self, func_addr: int, copies: list[frozenset[int]], layer: str = "discover") -> None:
        """Band every line of ``func_addr``'s pseudocode that renders one of the copies' instructions.

        Each ``layer`` is independent. The highlight waits for the function if it is still
        being decompiled, follows the pseudocode when it is regenerated, and goes away when
        another function is shown.
        """
        if copies:
            self.highlight_layers[layer] = (func_addr, copies)
        else:
            self.highlight_layers.pop(layer, None)
        self._view_call("on_pattern_highlight_changed")

    def set_pattern_highlight(self, name: str, on: bool) -> None:
        """Band the named pattern's matches in whatever function is shown: the calls the
        outlined ones became, found in the pseudocode itself, and the lines of the rest."""
        if on:
            self.highlighted_patterns.add(name)
        else:
            self.highlighted_patterns.discard(name)
        self._view_call("on_pattern_highlight_changed")

    def is_pattern_highlighted(self, name: str) -> bool:
        return name in self.highlighted_patterns

    @property
    def has_pattern_highlight(self) -> bool:
        """Whether anything is highlighted: a Discover family, a pattern's matches, or either in the disassembly."""
        return bool(self.highlight_layers or self.highlighted_patterns or self.disasm_pattern_addrs())

    def disasm_pattern_addrs(self) -> set[int]:
        disasm = self.workspace.view_manager.first_view_in_category("disassembly")
        return set(getattr(disasm, "pattern_highlight_addrs", ()))

    def clear_pattern_highlight(self) -> bool:
        """Drop every pattern highlight; returns whether there was any."""
        had = bool(self.highlight_layers or self.highlighted_patterns)
        disasm = self.workspace.view_manager.first_view_in_category("disassembly")
        if disasm is not None and disasm.clear_pattern_highlight():
            had = True
        self.highlight_layers.clear()
        self.highlighted_patterns.clear()
        self._view_call("on_pattern_highlight_cleared")
        if had:
            self._view_call("reload_patterns")
        return had

    def highlight_addrs(self) -> set[int]:
        """Every instruction address a highlight layer or a highlighted pattern asks for here."""
        if self._function.am_none:
            return set()
        func_addr = self._function.am_obj.addr
        addrs: set[int] = set()
        for layer, (layer_func, copies) in list(self.highlight_layers.items()):
            if layer_func != func_addr:
                # another function is on screen
                del self.highlight_layers[layer]
                continue
            addrs.update(*copies)
        kb = self.kb
        for name in list(self.highlighted_patterns):
            if kb is None or name not in kb.patterns:
                self.highlighted_patterns.discard(name)
                continue
            stats = kb.patterns.stats(func_addr, name)
            if stats is not None:
                addrs.update(stats.call_addrs)
                # an outlined match's statements are gone and match nothing; the rest still render
                addrs.update(*stats.match_addrs)
        return addrs

    def highlighted_call_names(self) -> set[str]:
        kb = self.kb
        names = set()
        for name in self.highlighted_patterns:
            stored = kb.patterns.get(name) if kb is not None else None
            if stored is not None:
                names.add(stored.pattern.call_name)
        return names

    def call_positions(self, call_names: set[str]) -> list[int]:
        """Where the pseudocode calls any of ``call_names``. An applied pattern is a call to its
        call name, so this needs neither the outliner pass's numbers nor a new decompilation."""
        if not call_names or self.codegen.am_none:
            return []
        positions = []
        for pos, elem in self.codegen.am_obj.map_pos_to_node.items():
            obj = elem.obj
            if not isinstance(obj, FunctionCallNode):
                continue
            callee = getattr(obj, "callee_func", None)
            target = callee.name if callee is not None else getattr(obj, "callee_target", None)
            if isinstance(target, str) and target in call_names:
                positions.append(pos)
        return positions

    def pattern_call_count(self, name: str) -> int:
        """How many times the pseudocode on screen calls the named pattern's call name."""
        kb = self.kb
        stored = kb.patterns.get(name) if kb is not None else None
        if stored is None:
            return 0
        return len(self.call_positions({stored.pattern.call_name}))

    def pattern_highlight_positions(self) -> list[int]:
        """The text positions of the pattern highlight: one position on every line it bands, in text order."""
        addrs = self.highlight_addrs()
        positions = self.call_positions(self.highlighted_call_names())
        if not (addrs or positions) or self.codegen.am_none:
            return []
        for pos, elem in self.codegen.am_obj.map_pos_to_node.items():
            ins = (getattr(elem.obj, "tags", None) or {}).get("ins_addr")
            if ins in addrs:
                positions.append(pos)
        return positions

    def pattern_highlight_rows(self) -> list[int]:
        """The lines the pattern highlight bands."""
        text = "" if self.codegen.am_none else self.codegen.text or ""
        return sorted({text.count("\n", 0, pos) for pos in self.pattern_highlight_positions()})

    def bookmark_positions(self) -> list[int]:
        """The text positions of the bookmarks of the function shown, one per bookmark rendered here."""
        if self.codegen.am_none or not self.rendered:
            return []
        positions = []
        for bookmark in self.instance.annotations.bookmarks:
            owner = self.function_at(bookmark.addr)
            if owner is not None and owner is not self._function.am_obj:
                continue
            pos = closest_node_pos(self.codegen, bookmark.addr)
            if pos is not None:
                positions.append(pos)
        return positions

    #
    # Find
    #

    def show_find_bar(self) -> None:
        """Open the find bar, seeded with the selection if it is one word."""
        if self.find_bar is None:
            return
        selected = self._view_call("selected_text") or ""
        self.find_bar.activate(selected if selected and " " not in selected else None)
        self._view_call("find_bar_opened")
        self.update_find_matches()

    def find_next(self) -> None:
        self._step_find_match(1)

    def find_previous(self) -> None:
        self._step_find_match(-1)

    def update_find_matches(self) -> None:
        """Find the query in the text again, and select the first match at or after the selection."""
        if self.find_bar is None:
            return
        pattern = self.find_bar.compile_query()
        text = self.plain_text()
        self.find_matches = [(m.start(), m.end()) for m in pattern.finditer(text)] if pattern is not None else []
        self.find_index = -1
        self._view_call("on_find_matches_changed")
        if self.find_matches:
            # jump to the first match at or after the selection start, so that recompiling the
            # query (typing, toggling case/regex) keeps the current match when it still matches
            pos = min(self.selection_range())
            index = next((i for i, (s, _) in enumerate(self.find_matches) if s >= pos), 0)
            self.select_find_match(index)
        else:
            self.find_bar.set_match_status(0, 0)

    def _step_find_match(self, delta: int) -> None:
        if not self.find_matches:
            self.update_find_matches()
            if not self.find_matches:
                return
            if delta > 0:
                return
        self.select_find_match((self.find_index + delta) % len(self.find_matches))

    def select_find_match(self, index: int) -> None:
        self.find_index = index
        start, end = self.find_matches[index]
        self._view_call("select_range", start, end)
        if self.find_bar is not None:
            self.find_bar.set_match_status(index, len(self.find_matches))

    def on_find_bar_closed(self) -> None:
        self.find_matches = []
        self.find_index = -1
        self._view_call("on_find_matches_changed")
        self._view_call("find_bar_closed")

    #
    # The context menu
    #

    def context_menu(self, *args, node: Any = AT_CURSOR, **kwargs) -> Menu | None:  # pylint:disable=unused-argument
        """
        The context menu for ``node`` (the node under the cursor by default), as QCCodeEdit.get_context_menu builds
        it: the node's groups of entries, the plugins' function and node entries, the AI entries, and Clear pattern
        highlights while there are some. Each entry's ``key`` names the QCCodeEdit action it stands for.
        """
        if node is AT_CURSOR and args:
            node = args[0]
        if node is AT_CURSOR:
            node = node_at_position(self.codegen, self.cursor_position()) if self.rendered else None
        self.selected_node = node if selects_node(node) else None
        menu = Menu("Pseudocode")
        plugins = getattr(self.workspace, "plugins", None)

        def add_keys(keys: Iterable[str]) -> None:
            for key in keys:
                if key in (BASE_SEPARATOR, LLM_SEPARATOR):
                    menu.add(MenuSeparator())
                    continue
                caption, shortcut, method = MENU_ACTIONS[key]
                menu.add(MenuEntry(caption, getattr(self, method), shortcut=shortcut, key=key))

        add_keys(context_menu_keys(node))
        if isinstance(node, FunctionNode) and plugins is not None:
            name = getattr(node, "name", None)
            if name in self.kb.functions:
                for entry in plugins.build_context_menu_functions([self.kb.functions[name]]):
                    menu.add(entry)
        if plugins is not None:
            for entry in plugins.build_context_menu_node(node):
                menu.add(entry)
        add_keys(_LLM_KEYS)
        if self.has_pattern_highlight:
            menu.add(MenuSeparator())
            add_keys(["action_clear_pattern_highlights"])
        return menu

    def select_node_at_cursor(self) -> Any:
        """Make the node under the cursor the one the node actions act on, as opening the context menu does."""
        node = node_at_position(self.codegen, self.cursor_position()) if self.rendered else None
        self.selected_node = node if selects_node(node) else None
        return self.selected_node

    #
    # Asking the user
    #

    def _ask(self, name: str, *args) -> bool:
        """Ask through the view's ``name`` if it has one; whether it did."""
        ask = self._view_attr(name)
        if ask is None:
            return False
        ask(*args)
        return True

    def predefined_types(self) -> dict[Any, SimType]:
        """The types a retype may name: the project's, and the function's local ones."""
        types = dict(self.kb.types)
        if not self._function.am_none:
            key = (self._function.addr, "pseudocode")
            if key in self.kb.decompilations:
                types.update(self.kb.decompilations[key].local_types)
        return types

    #
    # Renaming
    #

    def _node(self, node: Any) -> Any:
        return node if node is not None else self.selected_node

    @staticmethod
    def can_rename(node: Any) -> bool:
        if not isinstance(node, VariableNode | FunctionNode | FunctionCallNode | StructFieldNode | SimType):
            return False
        return not (
            isinstance(node, VariableNode) and isinstance(getattr(node, "variable", None), SimTemporaryVariable)
        )

    def rename_node(self, node: Any = None) -> None:
        """N: ask for a new name for ``node`` (the selected node), suggesting its variable's candidate names."""
        node = self._node(node)
        if not self.can_rename(node):
            return

        def then(name: str | None) -> None:
            if name is None:
                return
            if not is_valid_node_name(name):
                GlobalInfo.ui_services.message("warning", "Rename", f"{name!r} is not a valid name.")
                return
            if self.apply_rename(node, name.strip()):
                self.codegen.am_event()

        default = rename_default(node)
        suggestions = rename_suggestions(node)
        if not self._ask("ask_rename", node, default, suggestions, then):
            label = "New name" + (f" (suggestions: {', '.join(suggestions)})" if suggestions else "")
            ask_text("Rename", label, default, then)

    def _edit_hooks(self) -> WorkspaceEditHooks:
        return WorkspaceEditHooks(self.workspace)

    def apply_rename(self, node: Any, name: str, func: Any = None) -> bool:
        """
        Rename ``node`` to ``name``. Variables and functions are renamed through angr's edit layer (as the MCP tools
        do); a struct field or a type, which the layer has no operation for, by changing them directly, as is a
        variable the layer resolves to a different one than ``node`` (two variables of the same name). The caller
        re-renders. Returns whether something was renamed.
        """
        if self.codegen.am_none or self.codegen.cfunc is None:
            return False
        if func is None:
            func = self._function
        try:
            if self._rename_through_edits(node, name):
                return True
        except DecompilationEditError as ex:
            log.info("The edit layer cannot rename %r (%s); renaming it directly", node, ex)
        return rename_node_directly(self.workspace, self.instance, self.codegen.am_obj, node, name, func)

    def _rename_through_edits(self, node: Any, name: str) -> bool:
        project = self.instance.project.am_obj
        codegen = self.codegen.am_obj
        kb = codegen.kb
        cfunc = codegen.cfunc
        flavor = codegen.flavor
        obj: Any = node
        if isinstance(node, FunctionNode):
            func = kb.functions.get_by_addr(obj.addr)
            core_rename_function(
                project, func, name, kb=kb, hooks=self._edit_hooks(), flavor=flavor, strict_names=False, rerender=False
            )
            # the codegen on screen may not be the cached one of its flavor
            fnode: Any = node
            fnode.name = name
            fnode.demangled_name = name
            self.workspace.on_function_updated()
            return True
        if isinstance(node, FunctionCallNode):
            callee = getattr(node, "callee_func", None)
            if callee is None:
                return False
            core_rename_function(
                project,
                callee,
                name,
                kb=kb,
                hooks=self._edit_hooks(),
                flavor=flavor,
                strict_names=False,
                rerender=False,
            )
            self.workspace.on_function_updated()
            return True
        if isinstance(node, VariableNode):
            unified = getattr(node, "unified_variable", None)
            variable = getattr(node, "variable", None)
            func = kb.functions.get_by_addr(cfunc.addr)
            display_name = unified.name if unified is not None else getattr(variable, "name", None)
            if not display_name:
                return False
            resolved = resolve_variable(kb, func.addr, display_name, codegen=codegen, flavor=flavor)
            if unified is not None and resolved.unified is not unified:
                return False
            if unified is None and (resolved.kind != "global" or resolved.variable is not variable):
                return False
            core_rename_variable(
                project,
                func,
                display_name,
                name,
                kb=kb,
                hooks=self._edit_hooks(),
                flavor=flavor,
                strict_names=False,
                rerender=False,
                codegen=codegen,
            )
            return True
        return False

    #
    # Retyping
    #

    @staticmethod
    def can_retype(node: Any) -> bool:
        if not isinstance(node, VariableNode | FunctionNode | FunctionCallNode | StructFieldNode):
            return False
        return not (
            isinstance(node, VariableNode) and isinstance(getattr(node, "variable", None), SimTemporaryVariable)
        )

    def retype_node(self, node: Any = None, node_type: SimType | None = None) -> None:
        """Y: ask for a new type for ``node`` (the selected node) and apply it."""
        node = self._node(node)
        if not self.can_retype(node):
            return
        typed: Any = node
        if node_type is None and hasattr(typed, "type"):
            node_type = typed.type
        predefined = self.predefined_types()

        def then(text: str | None) -> None:
            if text is None:
                return
            valid, reason, new_type = parse_type_text(text, predefined)
            if not valid or new_type is None:
                GlobalInfo.ui_services.message("warning", "Specify a type", f"Invalid: {reason}")
                return
            self.apply_retype(node, new_type)

        default = retype_default(node, node_type)
        names = sorted(str(name) for name in predefined)
        if not self._ask("ask_type", node, default, names, then):
            ask_text("Specify a type", "New type", default, then)

    def set_user_prototype(self, proto: SimTypeFunction) -> dict:
        """
        Make ``proto`` the function's prototype, marked as the user's (the decompiler re-derives only the ones it
        inferred). Returns the renames and manual types the re-decompilation will drop.
        """
        result = core_set_function_prototype(
            self.instance.project.am_obj,
            self._function.am_obj,
            proto,
            kb=self.kb,
            hooks=self._edit_hooks(),
            invalidate_cache=False,  # decompile(reset_cache=True) drops the cache itself
        )
        return result.detail.get("user_edits") or {}

    def apply_retype(self, node: Any, new_node_type: Any) -> None:
        """Give ``node`` the type ``new_node_type`` and update the pseudocode (QCCodeEdit.retype_node's work)."""
        if new_node_type is None or node is None:
            return
        new_node_type = new_node_type.with_arch(self.instance.project.arch)
        if isinstance(node, FunctionNode):
            user_edits = self.set_user_prototype(new_node_type)
            self.codegen.am_event(event="retype_function", node=node, user_edits=user_edits)
            return

        if isinstance(node, StructFieldNode):
            snode: Any = node
            snode.struct_type.fields[snode.field] = new_node_type
            self.codegen.am_event(event="retype_variable", node=node)
            return

        if isinstance(node, VariableNode):
            unified: Any = getattr(node, "unified_variable", None)
            variable: Any = getattr(node, "variable", None)
            # a function argument: change the prototype
            if unified is not None and unified.is_function_argument:
                cfunc = self.codegen.cfunc
                for idx, arg in enumerate(cfunc.arg_list):
                    if arg is node:
                        new_proto = self._function.prototype.copy()
                        new_args = list(new_proto.args)
                        new_args[idx] = new_node_type
                        new_proto.args = tuple(new_args)
                        user_edits = self.set_user_prototype(new_proto)
                        self.codegen.am_event(event="retype_function", node=cfunc, user_edits=user_edits)
                        return

            is_local = unified is not None and unified in self.codegen.cfunc.get_unified_local_vars()
            if not self._retype_through_edits(node, new_node_type, is_local):
                dec_variables = self.codegen.kb.dec_variables
                if is_local:
                    dec_variables[self.codegen.cfunc.addr].set_variable_type(
                        variable, new_node_type, all_unified=True, mark_manual=True
                    )
                else:
                    dec_variables["global"].set_variable_type(
                        variable, new_node_type, all_unified=False, mark_manual=True
                    )
            self.codegen.am_event(event="retype_variable", node=node, variable=variable)

    def _retype_through_edits(self, node: Any, new_type: SimType, is_local: bool) -> bool:
        """Retype a local or a global variable through angr's edit layer, if it resolves to ``node``'s variable."""
        codegen = self.codegen.am_obj
        kb = codegen.kb
        unified = getattr(node, "unified_variable", None)
        variable = getattr(node, "variable", None)
        display_name = unified.name if (is_local and unified is not None) else getattr(variable, "name", None)
        if not display_name:
            return False
        func = kb.functions.get_by_addr(codegen.cfunc.addr)
        try:
            resolved = resolve_variable(kb, func.addr, display_name, codegen=codegen, flavor=codegen.flavor)
            if is_local and (resolved.kind != "local" or resolved.unified is not unified):
                return False
            if not is_local and (resolved.kind != "global" or resolved.variable is not variable):
                return False
            # the codegen event re-flows the types afterwards
            core_set_variable_type(
                self.instance.project.am_obj,
                func,
                display_name,
                new_type,
                kb=kb,
                hooks=self._edit_hooks(),
                flavor=codegen.flavor,
                reflow=False,
                allow_prototype_change=False,
                codegen=codegen,
            )
        except DecompilationEditError as ex:
            log.info("The edit layer cannot retype %r (%s); retyping it directly", node, ex)
            return False
        return True

    #
    # Comments
    #

    def comment(self, expr: bool = False, node: Any = None, inline: bool = True) -> None:
        """
        ``;``: comment the statement of the cursor's line (``expr``: the expression under the cursor). A one-line
        comment is edited on one line; a longer one, or ``inline=False``, in the multi-line editor.
        """
        addr = self.closest_insaddr(node, expr=expr)
        if addr is None:
            return
        if expr:
            self.comment_expr_at(addr)
            return
        # statement comments go into kb.comments so they survive re-decompilation and show up in
        # the disassembly too; the edit layer mirrors them into codegen.stmt_comments
        kb = self.kb
        text = "" if kb is None else kb.comments.get(addr, "")
        multiline = not inline or "\n" in text

        def then(answer: str | None) -> None:
            if answer is not None:
                self.workspace.set_comment(addr, answer)

        if not self._ask("ask_comment", addr, text, multiline, then):
            ask_text("Statement Comment", f"Comment at {addr:#x}:", text.replace("\n", " "), then)

    def comment_expr(self) -> None:
        """``?``: comment the expression under the cursor."""
        self.comment(expr=True)

    def comment_multiline(self) -> None:
        """``:``: edit the statement comment in the multi-line editor."""
        self.comment(inline=False)

    def comment_expr_at(self, addr: int) -> None:
        """Ask for the expression comment at ``addr`` and set it."""
        try:
            cdict = self.codegen.expr_comments
        except AttributeError:
            return
        text = cdict.get(addr, "")

        def then(answer: str | None) -> None:
            if answer is not None:
                self.set_expr_comment(addr, answer)

        if not self._ask("ask_expr_comment", addr, text, then):
            ask_text("Expression Comment", f"Expression comment at {addr:#x}:", text, then)

    def set_expr_comment(self, addr: int, text: str) -> None:
        """Set (or, with an empty text, remove) the expression comment at ``addr``, telling the plugins first."""
        try:
            cdict = self.codegen.expr_comments
        except AttributeError:
            return
        exists = addr in cdict
        if text:
            self.workspace.plugins.handle_comment_changed(addr, cdict.get(addr, ""), text, not exists, True)
            cdict[addr] = text
        elif exists:
            self.workspace.plugins.handle_comment_changed(addr, cdict[addr], "", False, True)
            del cdict[addr]
        self.codegen.am_event()

    #
    # The other node actions
    #

    def toggle_struct(self, node: Any = None) -> None:
        node = self._node(node)
        if not isinstance(node, VariableNode):
            return
        variable: Any = getattr(node, "variable", None)
        if isinstance(variable, SimVariable):
            ident = variable.ident
            if ident in self.vars_must_struct:
                self.vars_must_struct.remove(ident)
            elif ident is not None:
                self.vars_must_struct.add(ident)
            # decompile again
            self.view_or_self("decompile")()

    def _toggle(self, node: Any, attr: str, value: Any = None) -> None:
        node = self._node(node)
        if not hasattr(node, attr):
            return
        setattr(node, attr, (not getattr(node, attr)) if value is None else value)
        self.codegen.am_event()

    def collapse_expr(self, node: Any = None) -> None:
        self._toggle(node, "collapsed", True)

    def expand_expr(self, node: Any = None) -> None:
        self._toggle(node, "collapsed", False)

    def hex_constant(self, node: Any = None) -> None:
        self._toggle(node, "fmt_hex")

    def char_constant(self, node: Any = None) -> None:
        self._toggle(node, "fmt_char")

    def neg_constant(self, node: Any = None) -> None:
        self._toggle(node, "fmt_neg")

    def float_constant(self, node: Any = None) -> None:
        self._toggle(node, "fmt_float")

    def double_constant(self, node: Any = None) -> None:
        self._toggle(node, "fmt_double")

    def _cache(self):
        return self.kb.decompilations[(self._function.addr, "pseudocode")]

    def convert_to_ite_expr(self, node: Any = None) -> None:
        node = self._node(node)
        if not isinstance(node, ExpressionNode):
            return
        ailexpr = self.codegen.cnode2ailexpr.get(node, None)
        if ailexpr is None:
            return
        # which statement?
        addr = self.closest_insaddr(node)
        if addr is None:
            return
        cache = self._cache()
        if cache.ite_exprs is None:
            cache.ite_exprs = set()
        cache.ite_exprs.add((addr, ailexpr))
        self.view_or_self("decompile")(regen_clinic=False)

    def swap_binop_operands(self, node: Any = None) -> None:
        node = self._node(node)
        if not isinstance(node, BinaryOpNode):
            return
        ailexpr: Any = self.codegen.cnode2ailexpr.get(node, None)
        if ailexpr is None or not isinstance(ailexpr, BinaryOp):
            return

        oper = ailexpr.op
        negated_op = oper if oper in {"CmpEQ", "CmpNE"} else BinaryOp.COMPARISON_NEGATION.get(oper, None)
        if negated_op is None:
            return
        # which statement?
        addr = self.closest_insaddr(node)
        if addr is None:
            return

        cache: Any = self._cache()
        if cache.binop_operators is None:
            cache.binop_operators = {}
        block_addr: Any = getattr(ailexpr, "vex_block_addr", None)
        stmt_idx: Any = getattr(ailexpr, "vex_stmt_idx", None)
        op_desc = OpDescriptor(block_addr, stmt_idx, addr, oper)

        existing_op_desc_removed = False
        if negated_op in {"CmpEQ", "CmpNE"} or negated_op != oper:
            # remove existing descriptor if we are swapping the same binop expression twice
            existing_op_desc = OpDescriptor(block_addr, stmt_idx, addr, negated_op)
            if existing_op_desc in cache.binop_operators:
                del cache.binop_operators[existing_op_desc]
                existing_op_desc_removed = True

        if not existing_op_desc_removed:
            cache.binop_operators[op_desc] = negated_op
        self.view_or_self("decompile")(regen_clinic=False)

    def pattern_graph(self) -> Any:
        """The AIL graph a pattern is made from: the cached decompilation's. None, with a log line, if there is none."""
        if self.codegen.am_none or self._function.am_none:
            return None
        cache = self.kb.decompilations.get((self._function.addr, "pseudocode"))
        graph = cache.clinic.cc_graph if cache is not None and cache.clinic is not None else None
        if graph is None:
            log.warning("No AIL graph is cached for this function; decompile it first.")
        return graph

    def make_pattern(self, start: int, end: int, call_name: str, graph: Any = None) -> Any:
        """
        A pattern of the statements between text positions ``start`` and ``end``, which become calls to
        ``call_name``. Returns None, with a log line saying why, when there is none.
        """
        if start >= end:
            log.warning("Select the statements the pattern should cover first.")
            return None
        if graph is None:
            graph = self.pattern_graph()
        if graph is None:
            return None
        try:
            return PatternGenerator(self.codegen.am_obj, graph).generate_pattern(start, end, call_name.strip())
        except PatternGenerationError as ex:
            log.warning("Cannot make a pattern out of this selection: %s", ex)
            return None

    def create_pattern(self, call_name: str | None = None) -> Any:
        """
        Turn the selection into a pattern and open it in the pattern view. ``call_name``, the name of the call the
        pattern becomes, is asked for when not given. Returns the pattern view when it is open by the time this
        returns (the name was given, or the view asked for it and was answered at once), else None.
        """
        start, end = self.selection_range()
        if start >= end:
            log.warning("Select the statements the pattern should cover first.")
            return None
        graph = self.pattern_graph()
        if graph is None:
            return None
        shown: list[Any] = []

        def then(answer: str | None) -> None:
            if not answer or not answer.strip():
                return
            pattern = self.make_pattern(start, end, answer, graph)
            if pattern is None:
                return
            view = self.workspace._get_or_create_view("pattern", position="center")  # pylint:disable=protected-access
            if view is None:
                GlobalInfo.ui_services.message(
                    "info",
                    "Pattern",
                    f"Made the pattern {answer.strip()}; the pattern view is not in the terminal yet.",
                )
                return
            view.load_pattern(pattern, origin_func=self._function.addr)
            self.workspace.raise_view(view)
            shown.append(view)

        if call_name is not None:
            then(call_name)
        elif not self._ask("ask_pattern_name", then):
            ask_text("Pattern", "Name of the call the pattern becomes:", "", then)
        return shown[0] if shown else None

    def expr2armasm(self, node: Any = None) -> None:
        """Show the ARM THUMB assembly of the loads of the statement's AIL block, through the AIL2ARM32 plugin."""
        node = self._node(node)
        if not isinstance(node, VariableNode | IndexedVariableNode | VariableFieldNode | StructFieldNode):
            return
        current_node = stmt_node_at_position(self.codegen, self.cursor_position())
        if current_node is None:
            return
        ins_addr = current_node.tags.get("ins_addr", None)
        if ins_addr is None:
            return
        # traverse the stored clinic graph to find the AIL block
        cache: Any = self._cache()
        the_node: Any = None
        for block in cache.clinic.graph.nodes():
            if block.addr <= ins_addr < block.addr + block.original_size:
                the_node = block
                break
        if the_node is None:
            return
        converter = self.workspace.plugins.get_plugin_instance_by_name("AIL2ARM32")
        if converter is None:
            GlobalInfo.ui_services.message("warning", "AIL to ARM", "The AIL2ARM32 plugin is not active.")
            return

        def find_loads(expr: Any) -> list:
            if isinstance(expr, Load):
                return [expr]
            if isinstance(expr, Op):
                if isinstance(expr, UnaryOp):
                    return find_loads(expr.operand)
                loads = []
                operands: Any = getattr(expr, "operands", ())
                for operand in operands:
                    loads += find_loads(operand)
                return loads
            return []

        lst = []
        for stmt in the_node.statements:
            source = stmt.src if isinstance(stmt, Assignment) else stmt.data if isinstance(stmt, Store) else None
            if source is None:
                continue
            for load in find_loads(source):
                asm = converter.assemble(load, self._function.addr, load.ins_addr)
                lst.append((str(stmt), str(load), asm))

        text = f"The AIL block:\n{the_node!s}\n\n"
        for stmt, expr, asm in lst:
            text += f"Statement: {stmt}\n"
            text += f"Expression: {expr}\n"
            text += f"Assembly:\n{asm}\n\n"
        converter.display_output(text)

    def xref_target(self, node: Any = None) -> dict[str, Any] | None:
        """
        What the cross-references of ``node`` are asked for: ``addr``, ``xrefs_manager`` and ``dst_addr`` for a
        function, or ``addr``, ``variable_manager`` and ``variable`` for a variable. None for anything else.
        """
        node = self._node(node)
        if not isinstance(node, VariableNode | FunctionNode | FunctionCallNode):
            return None
        if isinstance(node, FunctionNode | FunctionCallNode):
            target: Any = node if isinstance(node, FunctionNode) else getattr(node, "callee_func", None)
            addr = target.addr
            return {"addr": addr, "xrefs_manager": self.instance.project.kb.xrefs, "dst_addr": addr}
        variable = getattr(node, "variable", None)
        func_addr_or_global = (
            "global" if isinstance(variable, SimMemoryVariable) and not isinstance(variable, SimStackVariable) else None
        )
        return {
            "addr": self.closest_insaddr(node),
            "variable_manager": self.view_or_self("variable_manager")(func_addr=func_addr_or_global),
            "variable": variable,
        }

    def xref_node(self, node: Any = None) -> None:
        """X: show the cross-references of ``node`` (the selected node)."""
        target = self.xref_target(node)
        if target is None:
            return
        show = getattr(self.workspace.main_window, "show_xrefs", None)
        if show is not None:
            show(**target)

    @staticmethod
    def hover_text(node: Any) -> str | None:
        """What hovering over ``node`` shows: a call's prototype."""
        return format_prototype(node)

    #
    # Text actions the view does
    #

    def copy(self) -> None:
        self._view_call("copy")

    def select_all(self) -> None:
        self._view_call("select_all")

    def zoom_in(self) -> None:
        self._view_call("zoom_in")

    def zoom_out(self) -> None:
        self._view_call("zoom_out")

    #
    # AI
    #

    def llm_refine_all(self) -> None:
        self.workspace.llm_refine_all()

    def llm_suggest_var_names(self) -> None:
        self.workspace.llm_suggest_variable_names()

    def llm_suggest_func_name(self) -> None:
        self.workspace.llm_suggest_function_name()

    def llm_suggest_var_types(self) -> None:
        self.workspace.llm_suggest_variable_types()


class HeadlessCodeView:
    """
    A pseudocode view that draws nothing: a presenter, a cursor, a selection and a find bar. Tests and scripts drive
    the presenter through it; it shows each new codegen as the frontends do (its text regenerated, its CodeDoc
    built).
    """

    category = "pseudocode"
    default_docking_position = "center"

    def __init__(self, workspace, instance: Instance) -> None:
        self.workspace = workspace
        self.instance = instance
        self.presenter = CodePresenter(workspace, instance)
        self.presenter.view = self
        self.cursor = 0
        self.sel_anchor: int | None = None
        self.find_bar = FindBarState()
        self.presenter.find_bar = self.find_bar
        self.find_bar.query_changed.connect(self.presenter.update_find_matches)
        self.find_bar.closed.connect(self.presenter.on_find_bar_closed)
        presenter = self.presenter
        presenter.function.am_subscribe(self._on_new_function)
        presenter.codegen.am_subscribe(self._on_codegen_changes)
        presenter.addr.am_subscribe(presenter.on_new_addr)
        presenter.current_node.am_subscribe(presenter.on_new_node)

    @property
    def index(self) -> int:
        return self.presenter.index

    @index.setter
    def index(self, value: int) -> None:
        self.presenter.index = value

    @property
    def caption(self) -> str:
        return self.presenter.caption

    @property
    def function(self) -> ObjectContainer:
        return self.presenter.function

    @property
    def _function(self) -> ObjectContainer:
        """The name the workspace reads the pseudocode view's function by (as on the Qt and the terminal views)."""
        return self.presenter.function

    @property
    def codegen(self) -> ObjectContainer:
        return self.presenter.codegen

    @property
    def addr(self) -> ObjectContainer:
        return self.presenter.addr

    def close(self) -> None:
        presenter = self.presenter
        presenter.function.am_unsubscribe(self._on_new_function)
        presenter.codegen.am_unsubscribe(self._on_codegen_changes)
        presenter.addr.am_unsubscribe(presenter.on_new_addr)
        presenter.current_node.am_unsubscribe(presenter.on_new_node)

    def _on_new_function(self, **kwargs) -> None:
        self.presenter.on_new_function(**kwargs)

    def _on_codegen_changes(self, already_regenerated: bool = False, event: str | None = None, **kwargs) -> None:
        presenter = self.presenter
        if presenter.codegen.am_none:
            presenter.doc = None
            presenter.rendered = False
            return
        if presenter.sync_kb_comments():
            already_regenerated = False
        presenter.regenerate_codegen(already_regenerated, event, **kwargs)
        doc = presenter.build_doc()
        presenter.rendered = True
        self.cursor = min(self.cursor, doc.text_length if doc is not None else 0)
        self.sel_anchor = None
        presenter.cursor_moved(self.cursor)

    def cursor_position(self) -> int:
        return self.cursor

    def selection_range(self) -> tuple[int, int]:
        if self.sel_anchor is None:
            return self.cursor, self.cursor
        return min(self.sel_anchor, self.cursor), max(self.sel_anchor, self.cursor)

    def selected_text(self) -> str:
        start, end = self.selection_range()
        return self.presenter.plain_text()[start:end]

    def set_cursor_position(self, pos: int) -> None:
        self.cursor = pos
        self.sel_anchor = None
        self.presenter.cursor_moved(pos)

    def select_range(self, start: int, end: int) -> None:
        self.sel_anchor = start
        self.cursor = end
        self.presenter.cursor_moved(end)


__all__ = [
    "CODE_COMMANDS",
    "CodeDoc",
    "CodePresenter",
    "HeadlessCodeView",
    "build_code_doc",
    "closest_node_pos",
    "context_menu_keys",
    "floor_comment_addr",
    "format_prototype",
    "is_valid_node_name",
    "node_at_position",
    "parse_type_text",
    "pseudocode_keymap",
    "register_code_commands",
    "related_text_chunks",
    "rename_default",
    "rename_node_directly",
    "rename_suggestions",
    "retype_default",
    "snap_comment_addr",
    "stmt_node_at_position",
    "type_text",
]
