"""Translate a selected decompiler storage location into a scoped runtime expression."""

from __future__ import annotations

from dataclasses import dataclass
from os.path import realpath
from typing import TYPE_CHECKING

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CIndexedVariable,
    CStructField,
    CVariable,
    CVariableField,
)
from angr.sim_type import (
    SimStruct,
    SimTypeArray,
    SimTypeDouble,
    SimTypeFixedSizeArray,
    SimTypeFloat,
    SimTypeNumOffset,
    SimTypePointer,
    SimUnion,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr.utils.types import unpack_typeref

if TYPE_CHECKING:
    from angr import Project

    from .gdb import GDBRuntime


class VariableBindingError(ValueError):
    """The selected expression has no sufficiently precise storage description."""


def verify_module_identity(runtime: GDBRuntime, path: str, build_id: str | bytes | None) -> None:
    if build_id is None:
        return
    expected = build_id.hex() if isinstance(build_id, bytes) else build_id
    matches = [module for module in runtime.snapshot()["modules"] if realpath(module["path"]) == realpath(path)]
    if len(matches) != 1 or matches[0].get("build_id") != expected:
        raise VariableBindingError("The analyzed module's build ID does not match the live image. Reload the analysis.")


def scalar_type(ty, size: int) -> str:
    """Use GDB builtins, which also work when the inferior has no debug types."""
    ty = unpack_typeref(ty) if ty is not None else None
    if isinstance(ty, SimTypeNumOffset):
        raise VariableBindingError(
            "Bitfields need an explicit GDB expression that preserves their bit offset and width."
        )
    if isinstance(ty, SimStruct | SimUnion | SimTypeArray | SimTypeFixedSizeArray):
        raise VariableBindingError("Select a scalar field or array element of this aggregate.")
    if isinstance(ty, SimTypeDouble):
        if size != 8:
            raise VariableBindingError("This floating-point format needs an explicit GDB type.")
        return "double"
    if isinstance(ty, SimTypeFloat):
        if size != 4:
            raise VariableBindingError("This floating-point format needs an explicit GDB type.")
        return "float"
    if isinstance(ty, SimTypePointer):
        return "void *"
    kinds = {1: "char", 2: "short", 4: "int", 8: "long long"}
    if size not in kinds:
        raise VariableBindingError("Select a scalar field or array element, or enter a GDB expression for this object.")
    return ("" if getattr(ty, "signed", False) else "unsigned ") + kinds[size]


def selection_at(codegen, position: int):
    """Recover the owning access for a field name or a constant array index."""
    mapping = codegen.map_pos_to_node
    node = mapping.get_node(position)
    if isinstance(node, CConstant):
        element = mapping.get_element(position)
        previous = mapping.get_node(element.start - 1)
        if isinstance(previous, CIndexedVariable) and previous.index is node:
            return previous
    if isinstance(node, CStructField):
        previous = mapping.get_element(position - 1)
        if previous is not None and isinstance(previous.obj, CVariableField) and previous.obj.field is node:
            return previous.obj
        for start, element in reversed(list(mapping.items())):
            if start >= position:
                continue
            if "\n" in codegen.text[start:position]:
                break
            if isinstance(element.obj, CVariableField) and element.obj.field is node:
                return element.obj
    return node


def instruction_at(codegen, position: int) -> int | None:
    """Use the selected node's instruction, or the nearest mapped statement on its line."""
    node = codegen.map_pos_to_node.get_node(position)
    address = (getattr(node, "tags", None) or {}).get("ins_addr")
    if isinstance(address, int):
        return address
    mapping = codegen.map_pos_to_addr
    if mapping is None:
        return None
    text = codegen.text
    start = text.rfind("\n", 0, position) + 1
    end = text.find("\n", position)
    if end == -1:
        end = len(text)
    for distance in range(max(position - start, end - position) + 1):
        for index in (position - distance, position + distance):
            if start <= index < end:
                address = (getattr(mapping.get_node(index), "tags", None) or {}).get("ins_addr")
                if isinstance(address, int):
                    return address
    return None


@dataclass(frozen=True)
class VariableBinding:
    """A recovered scalar location that must be resolved for each live session."""

    label: str
    kind: str
    size: int
    c_type: str
    module: str
    static_base: int
    location: int | str
    instruction: int | None = None
    offset: int = 0
    dereference: bool = False
    note: str = ""
    build_id: str | bytes | None = None

    def describe(self) -> dict:
        return {
            "label": self.label,
            "kind": self.kind,
            "size": self.size,
            "type": self.c_type,
            "module": self.module,
            "location": self.location,
            "instruction": self.instruction,
            "offset": self.offset,
            "dereference": self.dereference,
            "note": self.note,
        }

    def resolve(self, runtime: GDBRuntime, *, set_once: bool = False) -> dict:
        snap = runtime.snapshot()
        if snap["state"] != "stopped":
            raise VariableBindingError("Pause the live process before binding a decompiler variable.")
        verify_module_identity(runtime, self.module, self.build_id)
        trigger = None
        if self.instruction is not None and self.kind != "global":
            pc = runtime.static_to_runtime(self.instruction, self.static_base, self.module)
            trigger = f"*{pc:#x}"
            if set_once and snap.get("frame", {}).get("addr") != pc:
                raise VariableBindingError(f"This local is scoped to {pc:#x}. Break there before setting it once.")

        if self.kind == "global":
            address = runtime.static_to_runtime(int(self.location), self.static_base, self.module)
            base = f"{address:#x}"
        elif self.kind == "stack":
            base = f"($sp + ({self.location}))"
        else:
            raise VariableBindingError(f"Unsupported storage kind: {self.kind}")

        if self.dereference:
            base = f"(*(void **)({base}))"
        address_expression = f"((char *)({base}) + ({self.offset}))"
        expression = f"*({self.c_type} *)({address_expression})"
        return {"label": self.label, "expression": expression, "trigger": trigger, "note": self.note}


def describe_variable(project: Project, function, _codegen, node, instruction: int | None = None) -> VariableBinding:
    """Describe storage, retaining the exact instruction needed for an inferred stack binding."""
    if not isinstance(node, CVariable | CVariableField | CIndexedVariable):
        raise VariableBindingError("Select a variable, a scalar field, or a constant array element.")
    label = "".join(chunk for chunk, _ in node.c_repr_chunks() if chunk is not None)
    ty = getattr(node, "type", None)
    ty = unpack_typeref(ty) if ty is not None else None
    offset = 0
    dereference = False
    current = node
    while isinstance(current, CVariableField | CIndexedVariable):
        if isinstance(current, CVariableField):
            if dereference or (current.var_is_ptr and offset):
                raise VariableBindingError("Nested pointer fields need an explicit GDB expression.")
            dereference = current.var_is_ptr
            offset += current.field.offset
        else:
            if dereference:
                raise VariableBindingError("Indexed pointer chains need an explicit GDB expression.")
            index = getattr(current.index, "value", None)
            element_bits = getattr(current.type, "size", None)
            if not isinstance(index, int) or not isinstance(element_bits, int) or element_bits % 8:
                raise VariableBindingError("Select an element with a constant index, or enter a GDB expression.")
            offset += index * (element_bits // 8)
            if isinstance(unpack_typeref(getattr(current.variable, "type", None)), SimTypePointer):
                dereference = True
        current = current.variable
    if not isinstance(current, CVariable):
        raise VariableBindingError("Select a variable, a scalar field, or a constant array element.")
    variable = current.variable
    bits = getattr(ty, "size", None)
    size = bits // 8 if isinstance(bits, int) and bits > 0 and bits % 8 == 0 else variable.size
    c_type = scalar_type(ty, size)
    main = project.loader.find_object_containing(function.addr) or project.loader.main_object
    module = main.binary
    base = main.mapped_base
    instruction = instruction or (getattr(node, "tags", None) or {}).get("ins_addr")
    if isinstance(variable, SimStackVariable):
        cache = project.kb.decompilations.get((function.addr, "pseudocode"))
        tracker = getattr(getattr(cache, "clinic", None), "_spt", None)
        if instruction is None or tracker is None:
            raise VariableBindingError("This local has no instruction-specific stack map. Enter its GDB expression.")
        delta = tracker.offset_before(instruction, project.arch.sp_offset)
        if not isinstance(delta, int) or not isinstance(variable.offset, int):
            raise VariableBindingError("The stack offset is ambiguous at this instruction. Enter its GDB expression.")
        mask = (1 << project.arch.bits) - 1
        stack_offset = (variable.offset - delta) & mask
        if stack_offset & (1 << (project.arch.bits - 1)):
            stack_offset -= mask + 1
        return VariableBinding(
            label,
            "stack",
            size,
            c_type,
            module,
            base,
            stack_offset,
            instruction,
            offset,
            dereference,
            "Recovered stack location, sampled before this instruction in each invocation. "
            "A clamp writes at that point; later instructions can overwrite it.",
            build_id=getattr(main, "build_id", None),
        )
    if isinstance(variable, SimRegisterVariable):
        reg = project.arch.translate_register_name(variable.reg, variable.size)
        raise VariableBindingError(
            f"The recovered register ${reg} has no proven live range here. "
            "Check the original instruction and enter the live GDB expression."
        )
    if isinstance(variable, SimMemoryVariable) and isinstance(variable.addr, int):
        owner = project.loader.find_object_containing(variable.addr)
        if owner is None or not owner.binary:
            raise VariableBindingError("The variable does not belong to a mapped executable module.")
        return VariableBinding(
            label,
            "global",
            size,
            c_type,
            owner.binary,
            owner.mapped_base,
            variable.addr,
            offset=offset,
            dereference=dereference,
            note="Module-relative storage. The address is resolved against the current process mappings.",
            build_id=getattr(owner, "build_id", None),
        )
    raise VariableBindingError("This optimized temporary has no physical storage. Enter an explicit GDB expression.")


def list_variable_bindings(project: Project, function, codegen) -> list[dict]:
    """List selections by text position so MCP and the context menu use the same resolver."""
    result = []
    for position, element in codegen.map_pos_to_node.items():
        if not isinstance(element.obj, CVariable | CVariableField | CIndexedVariable):
            continue
        instruction = instruction_at(codegen, position)
        row = {"position": position}
        try:
            row.update(describe_variable(project, function, codegen, element.obj, instruction).describe())
            row["available"] = True
        except VariableBindingError as ex:
            row.update(label=codegen.text[position : position + element.length], available=False, reason=str(ex))
        result.append(row)
    return result
