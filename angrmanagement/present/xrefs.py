"""Cross-references without a toolkit: the table of references to a variable or to an address."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar, cast

from angr.knowledge_plugins.variables.variable_access import VariableAccess
from angr.knowledge_plugins.xrefs.xref import XRef
from angr.knowledge_plugins.xrefs.xref_types import XRefType

from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.data.instance import Instance


class XRefMode:
    """What a cross-reference list is about: a variable's accesses, or references to an address."""

    Variable = "variable"
    Address = "address"


def xref_title(instance: Instance | None, variable=None, dst_addr: int | None = None) -> str:
    """The title of a cross-reference list: the variable, the label at ``dst_addr``, or the address."""
    if variable is not None:
        return f"XRefs to variable {variable.name}({variable.ident})"
    if dst_addr is None:
        raise ValueError("Either variable or dst_addr must be specified.")
    lbl = None
    if instance is not None and instance.kb is not None:
        try:
            lbl = instance.kb.labels.get(dst_addr)
        except KeyError:
            lbl = None
    if lbl is not None:
        return f"XRefs to {lbl}"
    return f"XRefs to address {dst_addr:#x}"


def _instruction_text(instance: Instance, addr: int) -> str:
    text = instance.get_instruction_text_at(addr)
    return text if text is not None else "-=unavailable=-"


def _address_text(instance: Instance, addr: int) -> str:
    node = instance.cfg.get_any_node(addr, anyaddr=True)
    kb = instance.kb
    if node is not None and node.function_address is not None and kb is not None:
        return f"{addr:#x} ({kb.functions[node.function_address].name})"
    return hex(addr)


def _direction(ref_addr: int, here: int | None) -> str:
    if here is None:
        # when address is not available, we assume we are in pseudocode mode and at the top of this function
        return "down"
    if ref_addr < here:
        return "up"
    if ref_addr > here:
        return "down"
    return ""


class XRefsModel(ListTableModel[Any]):
    """
    The cross-references to a variable (``variable_manager`` and ``variable``) or to an address (``xrefs_manager``
    and ``dst_addr``). ``addr`` is where the user is, for the direction column.

    :param on_jump: Called with the instruction address of an activated row.
    """

    VARIABLE_HEADER: ClassVar[list[tuple[str, int]]] = [
        ("Direction", 70),
        ("Type", 50),
        ("Variable", 80),
        ("VarId", 80),
        ("PC", 160),
        ("Text", 300),
    ]
    ADDRESS_HEADER: ClassVar[list[tuple[str, int]]] = [("Direction", 70), ("Type", 50), ("PC", 160), ("Text", 300)]

    def __init__(
        self,
        instance: Instance | None,
        addr: int | None = None,
        variable_manager=None,
        variable=None,
        xrefs_manager=None,
        dst_addr: int | None = None,
        on_jump: Callable[[int], None] | None = None,
    ) -> None:
        super().__init__()
        self.instance = instance
        self.addr = addr
        self.variable_manager = variable_manager
        self.variable = variable
        self.xrefs_manager = xrefs_manager
        self.dst_addr = dst_addr
        self.on_jump = on_jump
        if variable_manager is not None and variable is not None:
            self.mode = XRefMode.Variable
        elif xrefs_manager is not None and dst_addr is not None:
            self.mode = XRefMode.Address
        else:
            raise ValueError("Unsupported mode. Either variable or dst_addr should be specified.")
        self.reload()

    @property
    def header(self) -> list[tuple[str, int]]:
        return self.VARIABLE_HEADER if self.mode == XRefMode.Variable else self.ADDRESS_HEADER

    @property
    def columns(self) -> list[Column]:
        last = len(self.header) - 1
        return [Column(name, width // 8, stretch=idx == last) for idx, (name, width) in enumerate(self.header)]

    @property
    def title(self) -> str:
        return xref_title(self.instance, self.variable, self.dst_addr)

    def reload(self) -> None:
        if self.variable_manager is not None:
            items = self.variable_manager.get_variable_accesses(self.variable, same_name=True)
            items = sorted(items, key=lambda item: item.location.ins_addr)
        elif self.xrefs_manager is not None:
            items = list(self.xrefs_manager.get_xrefs_by_dst(self.dst_addr))
            # Create XRef objects for addresses inside the CFG
            items += list(self._xrefs_from_control_flow_transitions())
            items = sorted(items, key=lambda item: item.ins_addr)
        else:
            items = []
        self.set_rows(items)

    def _xrefs_from_control_flow_transitions(self):
        if self.instance is None or self.dst_addr is None:
            return
        cfg = self.instance.cfg
        node = cfg.get_any_node(self.dst_addr)
        if node is None:
            return
        arch = self.instance.project.arch
        for pred in cfg.get_predecessors(node):
            if pred.instruction_addrs:
                if arch.branch_delay_slot and len(pred.instruction_addrs) > 1:
                    ins_addr = pred.instruction_addrs[-2]
                else:
                    ins_addr = pred.instruction_addrs[-1]
            else:
                ins_addr = pred.addr
            yield XRef(
                ins_addr=cast("int", ins_addr),
                block_addr=cast("int", pred.addr),
                stmt_idx=None,
                dst=self.dst_addr,
                xref_type=XRefType.Offset,
            )

    @staticmethod
    def ins_addr_of(item: Any) -> int | None:
        if isinstance(item, VariableAccess):
            return item.location.ins_addr
        if isinstance(item, XRef):
            return item.ins_addr
        return None

    def column_value(self, obj: Any, col: int) -> Any:
        name = self.header[col][0] if 0 <= col < len(self.header) else ""
        ins_addr = self.ins_addr_of(obj)
        if name == "Direction":
            return _direction(ins_addr, self.addr) if ins_addr is not None else ""
        if name == "Type":
            return obj.access_type if isinstance(obj, VariableAccess) else obj.type_string
        if name == "Variable":
            return obj.variable.name
        if name == "VarId":
            return obj.variable.ident
        if name == "PC":
            return _address_text(self.instance, ins_addr) if self.instance is not None and ins_addr is not None else ""
        if name == "Text":
            return (
                _instruction_text(self.instance, ins_addr) if self.instance is not None and ins_addr is not None else ""
            )
        return None

    def column_text(self, obj: Any, col: int) -> str:
        data = self.column_value(obj, col)
        if isinstance(data, int):
            return hex(data)
        return "" if data is None else str(data)

    def on_activate(self, obj: Any) -> None:
        ins_addr = self.ins_addr_of(obj)
        if ins_addr is not None and self.on_jump is not None:
            self.on_jump(ins_addr)
