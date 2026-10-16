"""
The display nodes of machine code: what each line of a disassembly block says, in which style.

Every node here knows its text and the style key of each part, and the selection state it shows, and nothing about
drawing. The Qt items (``QInstruction``, ``QOperand``, ``QBlockLabel``, ...) take their text and colours from these
nodes and lay them out in pixels; the terminal frontend asks a node for its :meth:`DisasmNode.lines` and writes them
into cells. ``disasm_view`` is the object that holds the display options (``show_address``, ``show_variable``,
``show_variable_identifier``): the Qt disassembly view, or the disassembly presenter.
"""

from __future__ import annotations

import enum
import logging
from typing import TYPE_CHECKING, Any

from angr.ailment.statement import Jump
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.disassembly import ConstantOperand, Instruction, IROp, MemoryOperand, RegisterOperand, Value
from angr.sim_variable import SimRegisterVariable

from angrmanagement.logic.disassembly.info_dock import OperandDescriptor, OperandHighlightMode
from angrmanagement.present.spans import Line, Span, split_lines
from angrmanagement.utils import (
    get_block_objects,
    get_function_header,
    get_label_text,
    get_out_branches_for_insn,
    get_string_for_display,
    is_printable,
    should_display_string_label,
)
from angrmanagement.utils.block_objects import FunctionHeader, Label, PhiVariable, Variables

from .ail import QAilObj
from .header import QFunctionHeader
from .vex import QIROpObj

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg.memory_data import MemoryData

    from angrmanagement.data.instance import Instance

    from .base import BlockTreeNode, BlockTreeNodeOptions

log = logging.getLogger(__name__)

#: The function header node is the block tree's.
FunctionHeaderNode = QFunctionHeader

# Gaps between the parts of a line, in characters, for frontends that lay out text in cells. The Qt items keep their
# own spacing in pixels.
ADDRESS_GAP = 2
LABEL_ADDRESS_GAP = 1
MNEMONIC_GAP = 1
COMMENT_GAP = 1
#: Where the mnemonic starts in the linear view, counted from the start of the address.
LINEAR_MNEMONIC_COLUMN = 20
#: Where the bytes of unknown data and memory data start in the linear view, counted from the start of the address.
LINEAR_DATA_COLUMN = 14
BYTE_AREA_GAP = 2

# Style keys for the parts of a line.
ADDRESS_STYLE = "disasm_view_node_address_color"
MNEMONIC_STYLE = "disasm_view_node_mnemonic_color"
COMMENT_STYLE = "disasm_view_comment_color"
STRING_STYLE = "disasm_view_string_color"
LABEL_STYLE = "disasm_view_label_color"
LABEL_SELECTED_STYLE = "disasm_view_label_highlight_color"
OPERAND_SELECTED_STYLE = "disasm_view_operand_select_color"
OPERAND_HIGHLIGHT_STYLE = "disasm_view_operand_highlight_color"
VARIABLE_STYLE = "disasm_view_variable_label_color"
VARIABLE_IDENT_STYLE = "disasm_view_variable_ident_color"
VARIABLE_OFFSET_STYLE = "disasm_view_variable_offset_color"
BRANCH_TARGETS_STYLE = "disasm_view_branch_target_text_color"
ALIGNMENT_STYLE = "disasm_view_alignment_color"
# Styles that are not configuration entries; the Qt frontend draws these in fixed colours.
PHI_VARIABLE_STYLE = "disasm.phi.variable"
PHI_IDENT_STYLE = "disasm.phi.ident"
PHI_PUNCTUATION_STYLE = "disasm.phi.punctuation"
DATA_DELIMITER_STYLE = "disasm.data.delimiter"


class CodeSelectionMode(enum.Enum):
    """What a click on a line of block tree text selects."""

    SELECT_INSTRUCTION = 1
    INVOKE_OBJ = 2
    NOOP = 3


class DisasmNode:
    """
    One line or group of lines of a disassembly block.

    :param addr:        The address the node shows.
    """

    addr: int

    def lines(self, disasm_view: Any, linear: bool = False) -> list[Line]:  # pylint:disable=unused-argument,no-self-use
        """The rows of text, styled; ``linear`` lays them out for the linear view."""
        return []

    def refresh(self) -> None:
        """Read the data the text comes from again (comments, labels, variables)."""

    def selection_style(self) -> str:  # pylint:disable=no-self-use
        """The background style key of the whole node while it is selected, or ""."""
        return ""


class OperandNode:
    """
    One operand of an instruction: its text, the variable it refers to and where a branch goes.

    The text parts are :attr:`label` (the operand as angr renders it, ``[rbp-0x10]``), :attr:`variable_label` (the
    operand rendered with its variable, empty when there is none), :attr:`branch_targets_text` (``[ a, b ]`` for an
    indirect branch) and :attr:`variable_ident` (``<ident>``).
    """

    def __init__(
        self,
        instance: Instance,
        func_addr,
        disasm,
        infodock,
        insn,
        operand,
        operand_index: int,
        is_branch_target: bool,
        is_indirect_branch: bool,
        branch_targets,
    ) -> None:
        self.instance = instance
        self.func_addr = func_addr
        self.disasm = disasm
        self.infodock = infodock
        self.variable_manager = infodock.variable_manager
        self.insn = insn
        self.operand = operand
        self.operand_index = operand_index
        self.is_branch_target = is_branch_target
        self.is_indirect_branch = is_indirect_branch
        self.branch_targets = branch_targets

        self.branch_target: int | None = None
        self.variable = None
        self.label: str = ""
        self.label_style = "disasm_view_operand_color"
        self.variable_label: str | None = None
        self.variable_ident: str | None = None
        self.branch_targets_shown = None
        self.branch_targets_text: str | None = None
        self.is_target_func: bool | None = None

        self.refresh()

    #
    # Properties
    #

    @property
    def text(self):
        return self.label

    @property
    def is_constant(self) -> bool:
        return isinstance(self.operand, ConstantOperand)

    @property
    def constant_value(self):
        if self.is_constant:
            return self.operand.cs_operand.imm
        return None

    @property
    def is_constant_memory(self) -> bool:
        return (
            isinstance(self.operand, MemoryOperand)
            and len(self.operand.values) == 1
            and isinstance(self.operand.values[0], Value)
            and isinstance(self.operand.values[0].val, int)
        )

    @property
    def constant_memory_value(self):
        if self.is_constant_memory:
            return self.operand.values[0].val
        return None

    @property
    def selected(self) -> bool:
        return self.infodock.is_operand_selected(self.insn.addr, self.operand_index)

    @property
    def operand_descriptor(self) -> OperandDescriptor:
        return OperandDescriptor(
            self.text,
            self.constant_value,
            func_addr=self.func_addr,
            variable_ident=self.variable.ident if self.variable is not None else None,
        )

    @property
    def jump_target(self) -> int | None:
        """Where a double click on the operand goes: its branch target, constant or constant memory address."""
        if self.branch_target is not None:
            return self.branch_target
        if self.is_constant:
            return self.constant_value
        if self.is_constant_memory:
            return self.constant_memory_value
        return None

    def background_style(self) -> str:
        """The background of the operand: selected, highlighted as equal to a selected operand, or none."""
        if self.selected:
            return OPERAND_SELECTED_STYLE
        for selected_operand_desc in self.infodock.selected_operands.values():
            if self.equals_for_highlighting_purposes(selected_operand_desc):
                return OPERAND_HIGHLIGHT_STYLE
        return ""

    #
    # Text
    #

    def spans(self, show_variable: bool, show_variable_identifier: bool) -> list[Span]:
        """The operand's text in cells: the label, then the variable, branch targets and identifier if shown."""
        out = [Span(self.label or "", self.label_style, self)]
        if self.variable_label and show_variable:
            out.append(Span(" ", "", self))
            out.append(Span(self.variable_label, VARIABLE_STYLE, self))
        if self.branch_targets_text:
            out.append(Span(" ", "", self))
            out.append(Span(self.branch_targets_text, BRANCH_TARGETS_STYLE, self))
        if self.variable is not None and show_variable_identifier and self.variable_ident:
            out.append(Span(" ", "", self))
            out.append(Span(self.variable_ident, VARIABLE_IDENT_STYLE, self))
        background = self.background_style()
        return [span.with_style(background) for span in out if span.text]

    def refresh(self) -> None:
        """Work out the text again (what ``QOperand._init_widgets`` computed before drawing)."""
        if self.is_branch_target:
            # a branch instruction

            is_target_func = bool(self.branch_targets and next(iter(self.branch_targets)) in self.disasm.kb.functions)

            self.label = self.operand.render()[0]
            self.is_target_func = is_target_func

            if self.is_indirect_branch:
                # indirect jump
                self.branch_targets_shown = self.branch_targets
                first_n_targets = self._first_n_branch_targets(self.branch_targets_shown, 3)
                if first_n_targets:
                    targets = []
                    for t in first_n_targets:
                        txt = None
                        if is_target_func:
                            # try to get a function
                            try:
                                target_func = self.disasm.kb.functions.get_by_addr(t)
                                txt = target_func.demangled_name
                            except KeyError:
                                pass
                        # is the address a label?
                        if txt is None and t in self.disasm.kb.labels:
                            txt = self.disasm.kb.labels[t]
                        if txt is None:
                            # use the hex text
                            txt = f"{t:#08x}"
                        targets.append(txt)
                    self.branch_targets_text = "[ " + ", ".join(targets) + " ]"
                else:
                    self.branch_targets_text = "[ unknown ]"

                if self.branch_targets_shown and len(self.branch_targets_shown) == 1:
                    self.branch_target = next(iter(self.branch_targets_shown))

            else:
                self.branch_target = self._branch_target_for_operand(self.operand, self.branch_targets)

        else:
            # not a branch
            self._init_variable_text()

        if self.branch_target or self.branch_targets_shown:
            if self.is_target_func:
                self.label_style = "disasm_view_target_addr_color"
            else:
                self.label_style = "disasm_view_antitarget_addr_color"
        elif self.is_constant:
            self.label_style = "disasm_view_operand_constant_color"
        else:
            self.label_style = "disasm_view_operand_color"

    def _init_variable_text(self) -> None:
        formatting = {}
        if isinstance(self.operand, MemoryOperand):
            variable_sort = "memory"
        elif isinstance(self.operand, RegisterOperand):
            variable_sort = "register"
        else:
            variable_sort = None

        # without displaying variable
        self.label = self.operand.render(formatting=formatting)[0]

        if variable_sort and self.variable_manager is not None:
            # try find the corresponding variable
            variable_and_offsets = self.variable_manager[self.func_addr].find_variables_by_insn(
                self.insn.addr, variable_sort
            )
            if variable_and_offsets:
                variable, offset = self._pick_variable(variable_and_offsets)

                if variable is not None:
                    self.variable = variable
                    self.variable_ident = f"<{variable.ident}>"
                    if offset is None:
                        offset = 0

                    variable_str = variable.name

                    ident = (self.insn.addr, "operand", self.operand_index)
                    if "custom_values_str" not in formatting:
                        formatting["custom_values_str"] = {}
                    if variable_sort == "memory":
                        custom_value_str = f"{variable_str}" if offset == 0 else f"{variable_str}[{offset}]"
                    else:
                        custom_value_str = ""

                    ##
                    # Hacks
                    ##
                    if self.infodock.induction_variable_analysis is not None:
                        r = self.infodock.induction_variable_analysis.variables.get(variable.ident, None)
                        if r is not None and r.expr.__class__.__name__ == "InductionExpr":
                            custom_value_str = f"i*{r.expr.stride}+{r.expr.init}"
                        if (
                            r is not None
                            and r.expr.__class__.__name__ == "Add"
                            and r.expr.operands[0].__class__.__name__ == "InductionExpr"
                        ):
                            custom_value_str = (
                                f"i*{r.expr.operands[0].stride}+{{r.expr.operands[0].init + r.expr.operands[1].value}}"
                            )

                    formatting["custom_values_str"][ident] = custom_value_str

                    if "show_prefix" not in formatting:
                        formatting["show_prefix"] = {}
                    formatting["show_prefix"][ident] = "False"

                    if "values_style" not in formatting:
                        formatting["values_style"] = {}
                    formatting["values_style"][ident] = "curly"

                # with variable displayed
                if variable_sort == "memory":
                    self.variable_label = self.operand.render(formatting=formatting)[0]
                else:
                    self.variable_label = ""

    #
    # Events
    #

    def activate(self, button: str, unique: bool = True, insn_pos=None) -> None:
        """A click: the left button toggles the operand's selection and selects its instruction with it."""
        if button != "left":
            return
        selected = self.infodock.toggle_operand_selection(
            self.insn.addr,
            self.operand_index,
            self.operand_descriptor,
            insn_pos=insn_pos,
            unique=unique,
        )
        if selected:
            # select the current instruction, too
            self.infodock.select_instruction(self.insn.addr, insn_pos=insn_pos, unique=True)

    def activate_double(self, button: str, jump_to) -> bool:
        """A double click with the left button jumps to :attr:`jump_target` through ``jump_to``; True if it did."""
        if button != "left":
            return False
        target = self.jump_target
        if target is None:
            return False
        jump_to(target, src_ins_addr=self.insn.addr, use_animation=True)
        return True

    #
    # Private methods
    #

    def _branch_target_for_operand(self, operand, branch_targets):
        if not branch_targets:
            return None

        if len(branch_targets) == 1:
            return next(iter(branch_targets))

        # there are more than one targets
        # we pick the one that complies with the operand's text
        # my solution is pretty hackish...

        imm = self.constant_value
        if imm is not None and imm in branch_targets:
            # problem solved
            return imm

        # try to render it
        rendered = operand.render()[0]
        for t in branch_targets:
            if rendered in (f"{t:x}", f"{t:#x}"):
                return t
            if t == rendered:
                return t

        # ouch not sure what to do
        log.warning('Cannot determine branch targets for operand "%s". Please report on GitHub.', rendered)
        # return a random one
        return next(iter(branch_targets))

    @staticmethod
    def _first_n_branch_targets(branch_targets, n):
        if not branch_targets:
            return []

        return list(branch_targets)[:n]

    def _pick_variable(self, variable_and_offsets):
        """
        Pick the corresponding variable for the current operand.

        :param list variable_and_offsets:   A list of variables and the offsets into each variable.
        :return:                            A tuple of variable and the offset.
        :rtype:                             tuple
        """

        if isinstance(self.operand, MemoryOperand):
            if len(variable_and_offsets) > 1:
                log.error("Instruction %#x has two memory operands. Please report it on GitHub.", self.insn.addr)
            return variable_and_offsets[0]

        if isinstance(self.operand, RegisterOperand):
            # there might be multiple register-type variables for an instruction. pick the right one is... not easy

            the_reg = self.operand.register
            if the_reg is None:
                # huh, it does not have a Register child
                return None, None

            reg_name = the_reg.reg
            arch = self.instance.project.arch

            if len(variable_and_offsets) == 1:
                # only one candidate...
                var, offset = variable_and_offsets[0]
                if arch.registers[reg_name][0] == var.reg:
                    return var, offset
                return None, None

            if self.operand_index > 0:
                # this is the source operand
                # which variable is read here?
                for var, offset in variable_and_offsets:
                    if arch.registers[reg_name][0] == var.reg and self._variable_has_access(
                        var, self.insn.addr, "read"
                    ):
                        return var, offset

                log.debug(
                    "Cannot find any source variable for operand %d at instruction %#x.",
                    self.operand_index,
                    self.insn.addr,
                )
                return None, None

            # this is the destination operand
            # which variable is written here?
            for var, offset in variable_and_offsets:
                if arch.registers[reg_name][0] == var.reg and self._variable_has_access(var, self.insn.addr, "write"):
                    return var, offset

            log.debug(
                "Cannot find any destination variable for operand %d at instruction %#x.",
                self.operand_index,
                self.insn.addr,
            )
            # just return the first one
            return None, None

        # what's this type? why am I here?
        log.error("_pick_variable: Unsupported operand type %s.", self.operand.__class__)

        return None, None

    def _variable_has_access(self, variable, ins_addr, access_type):
        accesses_by_variable = self.variable_manager[self.func_addr]._variable_accesses  # pylint:disable=protected-access
        if variable not in accesses_by_variable:
            log.error("Variable %s does not have any accessing records.", variable)
            return False

        accesses = accesses_by_variable[variable]
        return any(access.location.ins_addr == ins_addr and access.access_type == access_type for access in accesses)

    def equals_for_highlighting_purposes(self, other) -> bool:
        """
        Whether this operand is highlighted along with the selected operand ``other`` (an OperandDescriptor): the same
        variable in smart highlighting mode, the same text otherwise.
        """

        if other is None:
            return False

        highlight_mode = self.infodock.highlight_mode

        if highlight_mode == OperandHighlightMode.SAME_TEXT or self.variable is None:
            # when there is no related variable, we highlight as long as they have the same text
            return other.text == self.text
        if (
            highlight_mode == OperandHighlightMode.SAME_IDENT
            and self.variable is not None
            and other.variable_ident is not None
        ):
            return self.func_addr == other.func_addr and self.variable.ident == other.variable_ident

        return False

    # the name the Qt operand item used
    _equals_for_highlighting_purposes = equals_for_highlighting_purposes


class InsnNode(DisasmNode):
    """
    An instruction: address, mnemonic, operands with separators, and either its comments or the string it refers to.
    """

    COMMENT_PREFIX = "; "
    INTERSPERSE_ARGS = ", "

    def __init__(self, instance: Instance, func_addr, disasm, infodock, insn, out_branch) -> None:
        self.instance = instance
        self.func_addr = func_addr
        self.disasm = disasm
        self.infodock = infodock
        self.insn = insn
        self.out_branch = out_branch
        self.addr = insn.addr

        self.addr_text = f"{insn.addr:08x}"
        self.mnemonic = insn.mnemonic.render()[0]
        self.operands: list[OperandNode] = []
        self.comment: str | None = None
        self.string: str | None = None

        for i, operand in enumerate(insn.operands):
            is_branch_target = insn.type in ("branch", "call") and i == insn.branch_target_operand
            is_indirect_branch = insn.branch_type == "indirect"
            branch_targets = None
            if is_branch_target:
                if out_branch is not None:
                    branch_targets = out_branch.targets
                elif len(operand.children) == 1 and type(operand.children[0]) is Value:
                    # it does not create multiple branches. e.g., a call instruction
                    branch_targets = (operand.children[0].val,)
            self.operands.append(
                OperandNode(
                    instance,
                    func_addr,
                    disasm,
                    infodock,
                    insn,
                    operand,
                    i,
                    is_branch_target,
                    is_indirect_branch,
                    branch_targets,
                )
            )

        project: Any = instance.project
        if should_display_string_label(instance.cfg, insn.addr, project):
            # yes we should display a string label
            self.string = get_string_for_display(instance.cfg, insn.addr, project)
            if self.string is None:
                self.string = "<Unknown>"

        self.load_comment()

    @property
    def selected(self) -> bool:
        return self.infodock.is_instruction_selected(self.addr)

    @property
    def separators(self) -> list[str]:
        """The text between operands: one separator fewer than there are operands."""
        return [self.INTERSPERSE_ARGS] * max(len(self.operands) - 1, 0)

    @property
    def comment_lines(self) -> list[str] | None:
        """Each line of the comment with the comment prefix, or None when there is no comment."""
        if not self.comment:
            return None
        return [self.COMMENT_PREFIX + line for line in self.comment.split("\n")]

    def get_operand(self, operand_idx: int) -> OperandNode | None:
        if operand_idx < len(self.operands):
            return self.operands[operand_idx]
        return None

    def load_comment(self) -> None:
        if self.instance.kb is None:
            self.comment = None
            return

        annotations = self.instance.annotations
        lines = []
        own = annotations.inline_comment(self.insn.addr)
        if own:
            lines.append(own)
        # repeatable comments belonging to whatever this instruction references
        lines.extend(text for _, text in annotations.repeatable_comments_at(self.insn.addr))
        self.comment = "\n".join(lines) if lines else None

    def refresh(self) -> None:
        self.load_comment()
        for operand in self.operands:
            operand.refresh()

    def lines(self, disasm_view: Any, linear: bool = False) -> list[Line]:
        first = Line()
        if disasm_view.show_address:
            first.append(self.addr_text, ADDRESS_STYLE, self)
            if linear:
                first.pad(LINEAR_MNEMONIC_COLUMN)
            else:
                first.append(" " * ADDRESS_GAP, "", self)
        first.append(self.mnemonic, MNEMONIC_STYLE, self)
        first.append(" " * MNEMONIC_GAP, "", self)
        show_variable = disasm_view.show_variable
        show_ident = disasm_view.show_variable_identifier
        for idx, operand in enumerate(self.operands):
            if idx > 0:
                first.append(self.INTERSPERSE_ARGS, MNEMONIC_STYLE, self)
            first.extend(operand.spans(show_variable, show_ident))
        out = [first]
        comments = self.comment_lines if getattr(disasm_view, "show_comments", True) else None
        if comments:
            first.append(" " * COMMENT_GAP, "", self)
            column = first.width
            first.append(comments[0], COMMENT_STYLE, self)
            for text in comments[1:]:
                out.append(Line().pad(column).append(text, COMMENT_STYLE, self))
        elif self.string is not None:
            first.append(" " * COMMENT_GAP, "", self)
            first.append(self.string, STRING_STYLE, self)
        return out

    def activate(self, button: str, unique: bool = True, insn_pos=None) -> None:
        """
        A click on the instruction: the left button toggles its selection (``unique`` drops the others); the right
        button selects it if it is not selected yet. The view opens the context menu for a right click.
        """
        if button == "left":
            self.infodock.toggle_instruction_selection(self.addr, insn_pos=insn_pos, unique=unique)
        elif button == "right" and self.addr not in self.infodock.selected_insns:
            self.infodock.toggle_instruction_selection(self.addr, insn_pos=insn_pos, unique=True)


class LabelNode(DisasmNode):
    """A label line: the address and the label text (``loc_0x400754:`` or a name)."""

    def __init__(self, addr: int, text: str, infodock) -> None:
        self.addr = addr
        self.text = text
        self.infodock = infodock
        self.addr_text = f"{addr:08x}"

    @property
    def selected(self) -> bool:
        return self.infodock.is_label_selected(self.addr)

    def selection_style(self) -> str:
        return LABEL_SELECTED_STYLE if self.selected else ""

    def lines(self, disasm_view: Any, linear: bool = False) -> list[Line]:
        line = Line()
        if disasm_view.show_address:
            line.append(self.addr_text, ADDRESS_STYLE, self).append(" " * LABEL_ADDRESS_GAP, "", self)
        line.append(self.text, LABEL_STYLE, self)
        return [line.restyled(self.selection_style())]

    def activate(self, button: str) -> None:
        """A click selects the label; the view opens the label's context menu for a right click."""
        if button == "left":
            self.infodock.select_label(self.addr)
        elif button == "right":
            self.infodock.unselect_all_labels()
            self.infodock.select_label(self.addr)


class VariableNode(DisasmNode):
    """A stack variable at the head of a function: name, identifier and offset."""

    def __init__(self, variable, infodock) -> None:
        self.variable = variable
        self.infodock = infodock
        self.addr = 0
        self.name = "" if not variable.name else variable.name
        self.ident = "<%s>" % ("" if not variable.ident else variable.ident)
        self.offset_text = f"{variable.offset:#x}"

    @property
    def selected(self) -> bool:
        return self.infodock.is_variable_selected(self.variable)

    def lines(self, disasm_view: Any, linear: bool = False) -> list[Line]:
        line = Line().append(self.name, VARIABLE_STYLE, self).append(" ", "", self)
        if disasm_view.show_variable_identifier:
            line.append(self.ident, VARIABLE_IDENT_STYLE, self).append(" ", "", self)
        line.append(" ", "", self).append(self.offset_text, VARIABLE_OFFSET_STYLE, self)
        return [line.restyled(OPERAND_SELECTED_STYLE if self.selected else "")]

    def activate(self, button: str, unique: bool = True) -> None:
        if button == "left":
            self.infodock.toggle_variable_selection(self.variable, unique=unique)


class PhiVariableNode(DisasmNode):
    """A phi variable: ``{name} <ident> = ɸ(<a>, <b>)``. It shows only with variable identifiers."""

    PHI = "ɸ("

    def __init__(self, phi_variable) -> None:
        self.phi = phi_variable.variable  # the major variable
        self.variables = phi_variable.variables  # the sub variables
        self.addr = 0
        self.variable_name = "{%s}" % ("Unk" if not self.phi.name else self.phi.name)
        self.variable_ident = "<%s>" % ("Unk" if not self.phi.ident else self.phi.ident)
        self.subvar_names = ["Unk" if not subvar.name else subvar.name for subvar in self.variables]
        self.subvar_idents = ["<%s>" % ("Unk" if not subvar.ident else subvar.ident) for subvar in self.variables]

    def lines(self, disasm_view: Any, linear: bool = False) -> list[Line]:
        if disasm_view.show_variable_identifier is False:
            return []
        line = Line().append(self.variable_name, PHI_VARIABLE_STYLE, self)
        line.append(" ", "", self).append(self.variable_ident, PHI_IDENT_STYLE, self)
        line.append(" = ", PHI_PUNCTUATION_STYLE, self).append(self.PHI, PHI_VARIABLE_STYLE, self)
        for idx, ident in enumerate(self.subvar_idents):
            if idx:
                line.append(", ", PHI_PUNCTUATION_STYLE, self)
            line.append(ident, PHI_VARIABLE_STYLE, self)
        line.append(")", PHI_VARIABLE_STYLE, self)
        return [line]


class FunctionCommentNode(DisasmNode):
    """The function comment, as lines above the function's first block; no lines when there is none."""

    COMMENT_PREFIX = "; "

    def __init__(self, instance: Instance, func_addr: int) -> None:
        self.instance = instance
        self.addr = func_addr
        self.text_lines: list[str] = []
        self.refresh()

    def refresh(self) -> None:
        text = None
        if self.instance.kb is not None:
            text = self.instance.annotations.function_comment(self.addr)
        self.text_lines = [self.COMMENT_PREFIX + line for line in text.split("\n")] if text else []

    def lines(self, disasm_view: Any, linear: bool = False) -> list[Line]:
        return [Line().append(text, COMMENT_STYLE, self) for text in self.text_lines]


class CodeNode(DisasmNode):
    """
    A line of block tree text (an AIL statement, a lifter IR op or the function header), with the address it starts
    at shown before it.

    :param addr:            The address shown, or None.
    :param tree:            The block tree node.
    :param selection_mode:  What a click selects.
    :param kind:            ``"header"`` (the function header), ``"ail"`` (an AIL statement) or ``"ir"`` (a lifter
                            IR op).
    """

    def __init__(
        self,
        addr: int | None,
        tree: BlockTreeNode,
        infodock,
        selection_mode: CodeSelectionMode = CodeSelectionMode.SELECT_INSTRUCTION,
        kind: str = "ir",
    ) -> None:
        self.addr = addr  # type: ignore[assignment]
        self.tree = tree
        self.infodock = infodock
        self.selection_mode = selection_mode
        self.kind = kind
        self.addr_text = "" if addr is None else f"{addr:08x}"
        if tree.parent is None:
            tree.parent = self

    def update(self) -> None:
        """What a block tree node calls when it changes; the frontend redraws on the selection events."""

    def should_highlight(self) -> bool:
        match self.selection_mode:
            case CodeSelectionMode.SELECT_INSTRUCTION:
                if self.addr is not None and self.infodock.is_instruction_selected(self.addr):
                    return True
                return self.tree.should_highlight() or self.tree.should_highlight_line
            case CodeSelectionMode.INVOKE_OBJ:
                return self.tree.should_highlight() or self.tree.should_highlight_line
        return False

    def selection_style(self) -> str:
        return "disasm_view_node_instruction_selected_background_color" if self.should_highlight() else ""

    def lines(self, disasm_view: Any, linear: bool = False) -> list[Line]:
        text_lines = split_lines(self.tree.render())
        prefix = 0
        if disasm_view.show_address and self.tree.display_address:
            prefix = len(self.addr_text) + ADDRESS_GAP
        out = [Line() for _ in range(self.tree.top_margin_lines)]
        for idx, text_line in enumerate(text_lines):
            line = Line()
            if prefix and idx == 0:
                line.append(self.addr_text, ADDRESS_STYLE, self).append(" " * ADDRESS_GAP, "", self)
            elif prefix:
                line.pad(prefix)
            line.extend(text_line.spans)
            out.append(line)
        out.extend(Line() for _ in range(self.tree.bottom_margin_lines))
        background = self.selection_style()
        return [line.restyled(background) for line in out] if background else out

    def activate(self, button: str) -> None:
        """A click on the line outside the tree's text: select the instruction it starts, as the Qt item does."""
        if button == "left" and self.selection_mode == CodeSelectionMode.SELECT_INSTRUCTION and self.addr is not None:
            self.infodock.select_instruction(self.addr)


class MemoryDataNode(DisasmNode):
    """
    A data item in the linear view: the address and label, then 16 bytes per line with their characters.

    :attr:`rows` holds, per line, ``(address text, byte offset, [(byte text, style)], [(character, style)])``; byte
    offset is how far into its 16-byte line the first byte sits (the item need not start on a line boundary).
    """

    def __init__(self, instance: Instance, infodock, addr: int, memory_data: MemoryData, bytes_per_line: int = 16):
        self.instance = instance
        self.infodock = infodock
        self.addr = addr
        self.memory_data = memory_data
        self.bytes_per_line = bytes_per_line
        self.addr_text = f"{addr:08x}"
        self.label: str | None = None
        self.bytes: list[int | str] = []
        self.rows: list[tuple[str, int, list[tuple[str, str]], list[tuple[str, str]]]] = []
        self._load_bytes()
        self.refresh()

    def _load_bytes(self) -> None:
        self.bytes = []
        if self.memory_data.content:
            cnt = self.memory_data.content
            if self.memory_data.size is not None:
                cnt = cnt[: self.memory_data.size]
            self.bytes += list(cnt)

        if self.memory_data.size is not None and len(self.bytes) < self.memory_data.size:
            # load more from mapped memory
            start_address = self.memory_data.addr + len(self.bytes)
            size = self.memory_data.size - len(self.bytes)
            try:
                mem_bytes = self.instance.project.loader.memory.load(start_address, size)
            except KeyError:
                mem_bytes = b""
            self.bytes += list(mem_bytes) + ["??"] * (size - len(mem_bytes))

    def refresh(self) -> None:
        self.label = get_label_text(self.addr, self.instance.kb) or None
        self.rows = []
        addr = self.addr
        i = 0
        while i < len(self.bytes):
            byte_offset = addr % self.bytes_per_line
            end_pos = i + self.bytes_per_line if byte_offset == 0 else self.bytes_per_line - byte_offset
            all_bytes = self.bytes[i:end_pos]
            self.rows.append((f"{addr:08x}", byte_offset, *self._line(byte_offset, all_bytes)))
            addr += end_pos - i
            i = end_pos

    def _line(self, byte_offset: int, all_bytes) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
        byte_parts: list[tuple[str, str]] = []
        for idx, byt in enumerate(all_bytes):
            if isinstance(byt, int):
                style = (
                    "disasm_view_printable_byte_color" if is_printable(byt) else "disasm_view_unprintable_byte_color"
                )
                byte_parts.append((f"{byt:02x}", style))
            else:  # str, usually because it is an unknown byte, in which case the str is "??"
                byte_parts.append((byt, "disasm_view_unknown_byte_color"))
            line_chars = byte_offset + idx + 1  # the number of existing characters on this line, including spaces
            if line_chars % 8 == 0 and line_chars != self.bytes_per_line:
                # a delimiter
                byte_parts.append(("-", DATA_DELIMITER_STYLE))

        char_parts: list[tuple[str, str]] = []
        for byt in all_bytes:
            if isinstance(byt, int):
                if is_printable(byt):
                    char_parts.append((chr(byt), "disasm_view_printable_character_color"))
                else:
                    char_parts.append((".", "disasm_view_unprintable_character_color"))
            else:
                char_parts.append(("?", "disasm_view_unknown_character_color"))
        return byte_parts, char_parts

    @property
    def selected(self) -> bool:
        return self.infodock.is_label_selected(self.addr)

    def selection_style(self) -> str:
        return LABEL_SELECTED_STYLE if self.selected else ""

    def lines(self, disasm_view: Any, linear: bool = True) -> list[Line]:
        head = Line().append(self.addr_text, ADDRESS_STYLE, self)
        if self.label:
            head.append(" " * ADDRESS_GAP, "", self).append(self.label, LABEL_STYLE, self)
        out = [head]
        for addr_text, byte_offset, byte_parts, char_parts in self.rows:
            line = Line().append(addr_text, ADDRESS_STYLE, self).pad(LINEAR_DATA_COLUMN)
            line.append("   " * byte_offset, "", self)
            shown = 0
            for text, style in byte_parts:
                if text == "-" and style == DATA_DELIMITER_STYLE:
                    # the delimiter takes the place of the space after the eighth byte
                    line.spans.pop()
                    line.append("-", style, self)
                    continue
                line.append(text, style, self).append(" ", "", self)
                shown += 1
            missing = self.bytes_per_line - byte_offset - shown
            line.append("   " * max(missing, 0), "", self).append(" " * BYTE_AREA_GAP, "", self)
            line.append(" " * byte_offset, "", self)
            for ch, style in char_parts:
                line.append(ch, style, self)
            out.append(line)
        return [line.restyled(self.selection_style()) for line in out]

    def activate(self, button: str) -> None:
        """A click selects the item's label; the view opens the label's context menu for a right click."""
        if button in ("left", "right"):
            self.infodock.unselect_all_labels()
            self.infodock.select_label(self.addr)


class UnknownNode(DisasmNode):
    """Bytes the CFG did not explain, 16 per line, at most 100 lines."""

    DEFAULT_TEXT = "Unknown"
    BYTES_PER_LINE = 16
    MAX_LINES = 100

    def __init__(self, addr: int, bytes_) -> None:
        self.addr = addr
        self.bytes = bytes_
        self.addr_text = f"{addr:08x}"
        self.byte_lines: list[str] = []
        self._init_lines()

    def _init_lines(self) -> None:
        self.byte_lines = []
        if self.bytes:
            line = ""
            for i, b in enumerate(self.bytes):
                line += f"{b:02x} "
                if i > 0 and (i + 1) % self.BYTES_PER_LINE == 0:
                    self.byte_lines.append(line)
                    line = ""
                    if len(self.byte_lines) > self.MAX_LINES:
                        self.byte_lines.append("Remaining lines are omitted")
                        break
            if line:
                self.byte_lines.append(line)
        else:
            self.byte_lines.append(self.DEFAULT_TEXT)

    def addr_of_line(self, line_idx: int) -> int:
        """The address of the first byte on line ``line_idx``, clamped to the last byte."""
        addr = self.addr + max(line_idx, 0) * self.BYTES_PER_LINE
        if self.bytes:
            addr = min(addr, self.addr + len(self.bytes) - 1)
        return addr

    def lines(self, disasm_view: Any, linear: bool = True) -> list[Line]:
        out = []
        for idx, text in enumerate(self.byte_lines):
            line = Line()
            if idx == 0:
                line.append(self.addr_text, ADDRESS_STYLE, self)
            line.pad(LINEAR_DATA_COLUMN).append(text, "disasm_view_unprintable_byte_color", self)
            out.append(line)
        return out


class AlignmentNode(DisasmNode):
    """An alignment function in the linear view: one summary line, after an empty one."""

    def __init__(self, addr: int, size: Any) -> None:
        self.addr = addr
        self.size = size
        self.addr_text = f"{addr:08x}"
        self.text = f"[alignment_chunk]: {size:#x} bytes"

    def lines(self, disasm_view: Any, linear: bool = True) -> list[Line]:
        line = Line()
        if disasm_view.show_address:
            line.append(self.addr_text, ADDRESS_STYLE, self).append(" " * ADDRESS_GAP, "", self)
        line.append(self.text, ALIGNMENT_STYLE, self)
        return [Line(), line]


def _header_node(func_addr: int, header: FunctionHeader, infodock) -> CodeNode:
    tree = QFunctionHeader(
        func_addr, header.name, header.demangled_name, header.prototype, header.args, infodock, parent=None
    )
    return CodeNode(func_addr, tree, infodock, CodeSelectionMode.INVOKE_OBJ, kind="header")


def build_block_nodes(
    instance: Instance,
    func_addr: int,
    disasm,
    infodock,
    cfg_nodes,
    out_branches,
    options: BlockTreeNodeOptions,
) -> list[DisasmNode]:
    """
    The nodes of one disassembly block, top to bottom, as the Qt block lays them out.

    :param disasm:          The Disassembly analysis of the function, or its Clinic for AIL.
    :param cfg_nodes:       The CFG nodes (or AIL blocks) the block shows.
    :param out_branches:    The out branches of the block's supernode, or None.
    :param options:         What the block tree text shows (variables, conditional jump targets).
    """
    nodes: list[DisasmNode] = []
    if cfg_nodes and cfg_nodes[0].addr == func_addr:
        nodes.append(FunctionCommentNode(instance, func_addr))

    if isinstance(disasm, Clinic):
        nodes.extend(_ail_block_nodes(instance, func_addr, disasm, infodock, cfg_nodes, options))
    else:
        nodes.extend(_disassembly_block_nodes(instance, func_addr, disasm, infodock, cfg_nodes, out_branches))
    return nodes


def _ail_block_nodes(instance: Instance, func_addr: int, disasm, infodock, cfg_nodes, options) -> list[DisasmNode]:
    nodes: list[DisasmNode] = []
    addr = cfg_nodes[0].addr

    if addr == func_addr:
        kb: Any = instance.kb
        func_header = get_function_header(kb.functions, func_addr)
        if func_header is not None:
            # this is the function header block
            nodes.append(_header_node(func_addr, func_header, infodock))

    if addr in disasm.kb.labels:
        nodes.append(LabelNode(addr, get_label_text(addr, disasm.kb), infodock))

    # always add the block name as a label and instruction:
    nodes.append(LabelNode(addr, f"loc_{hex(addr)}:", infodock))

    for bi, block in enumerate(cfg_nodes):
        for i, stmt in enumerate(block.statements):
            if i == len(block.statements) - 1 and bi != len(cfg_nodes) - 1 and isinstance(stmt, Jump):
                continue
            code_obj = QAilObj(
                stmt,
                instance,
                infodock,
                block_addr=block.addr,
                block_idx=block.idx,
                stmt_idx=i,
                parent=None,
                options=options,
            )
            nodes.append(CodeNode(stmt.tags.get("ins_addr"), code_obj, infodock, kind="ail"))
    return nodes


def _disassembly_block_nodes(
    instance: Instance, func_addr: int, disasm, infodock, cfg_nodes, out_branches
) -> list[DisasmNode]:
    nodes: list[DisasmNode] = []
    for obj in get_block_objects(disasm, cfg_nodes, func_addr):
        if isinstance(obj, Instruction):
            out_branch = get_out_branches_for_insn(out_branches, obj.addr)
            nodes.append(InsnNode(instance, func_addr, disasm, infodock, obj, out_branch))
        elif isinstance(obj, Label):
            nodes.append(LabelNode(obj.addr, obj.text, infodock))
        elif isinstance(obj, IROp):
            nodes.append(CodeNode(obj.addr, QIROpObj(obj, infodock, parent=None), infodock, kind="ir"))
        elif isinstance(obj, PhiVariable):
            if not isinstance(obj.variable, SimRegisterVariable):
                nodes.append(PhiVariableNode(obj))
        elif isinstance(obj, Variables):
            nodes.extend(VariableNode(var, infodock) for var in obj.variables)
        elif isinstance(obj, FunctionHeader):
            nodes.append(_header_node(func_addr, obj, infodock))
    return nodes


__all__ = [
    "AlignmentNode",
    "CodeNode",
    "CodeSelectionMode",
    "DisasmNode",
    "FunctionCommentNode",
    "FunctionHeaderNode",
    "InsnNode",
    "LabelNode",
    "MemoryDataNode",
    "OperandNode",
    "PhiVariableNode",
    "UnknownNode",
    "VariableNode",
    "build_block_nodes",
]
