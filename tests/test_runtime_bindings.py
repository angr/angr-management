from __future__ import annotations

import unittest
from itertools import count
from types import SimpleNamespace
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen.base import PositionMapping
from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CIndexedVariable,
    CStructField,
    CVariable,
    CVariableField,
)
from angr.sim_type import SimStruct, SimTypeFixedSizeArray, SimTypeInt, SimTypePointer
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from archinfo import ArchAMD64

from angrmanagement.logic.debugger.variable_binding import (
    VariableBinding,
    VariableBindingError,
    describe_variable,
    instruction_at,
    scalar_type,
    selection_at,
    verify_module_identity,
)


class BindingRuntime:
    """A stopped target with a known relocation for testing storage expressions."""

    def __init__(self, pc=0x55551020):
        self.pc = pc
        self.state = "stopped"

    def snapshot(self):
        return {"state": self.state, "frame": {"addr": self.pc}}

    @staticmethod
    def static_to_runtime(address, base, module):
        if module != "/game":
            raise ValueError("Module identity mismatch")
        return address - base + 0x55550000


class TestRuntimeBindings(unittest.TestCase):
    """Check recovered locations before they become live GDB expressions."""

    def setUp(self):
        self.arch = ArchAMD64()
        self.module = SimpleNamespace(binary="/game", mapped_base=0x400000)
        self.project: Any = SimpleNamespace(
            arch=self.arch,
            loader=SimpleNamespace(main_object=self.module, find_object_containing=lambda _: self.module),
            kb=SimpleNamespace(decompilations={}),
        )
        self.codegen = SimpleNamespace(
            project=self.project,
            next_ident=lambda name: name,
            next_node_idx=count().__next__,
            display_vvar_ids=False,
            const_formats={},
        )
        self.function = SimpleNamespace(addr=0x401000)

    @staticmethod
    def runtime(pc=0x55551020) -> Any:
        return BindingRuntime(pc)

    def variable(self, variable):
        return CVariable(variable, variable_type=SimTypeInt(), codegen=self.codegen)

    def test_module_relative_global_and_member(self):
        node = self.variable(SimMemoryVariable(0x404020, 4, name="score"))
        binding = describe_variable(self.project, self.function, self.codegen, node)
        resolved = binding.resolve(self.runtime())
        self.assertIn("0x55554020", resolved["expression"])
        self.assertIsNone(resolved["trigger"])
        member = VariableBinding("player.life", "global", 4, "int", "/game", 0x400000, 0x404020, offset=12)
        self.assertIn("+ (12)", member.resolve(self.runtime())["expression"])

    def test_stack_offsets_are_normalized_at_hook_instruction(self):
        tracker = SimpleNamespace(offset_before=lambda address, register: (1 << 64) - 40)
        self.project.kb.decompilations[(self.function.addr, "pseudocode")] = SimpleNamespace(
            clinic=SimpleNamespace(_spt=tracker)
        )
        node = self.variable(SimStackVariable(-24, 4, name="score"))
        binding = describe_variable(self.project, self.function, self.codegen, node, 0x401020)
        self.assertEqual(binding.location, 16)
        resolved = binding.resolve(self.runtime())
        self.assertIn("$sp + (16)", resolved["expression"])
        self.assertEqual(resolved["trigger"], "*0x55551020")
        with self.assertRaisesRegex(VariableBindingError, "Break there"):
            binding.resolve(self.runtime(pc=0x55551234), set_once=True)
        self.assertEqual(binding.resolve(self.runtime(), set_once=True), resolved)

    def test_ambiguous_stack_and_temporary_are_explicit(self):
        node = self.variable(SimStackVariable(-24, 4, name="score"))
        with self.assertRaisesRegex(VariableBindingError, "stack map"):
            describe_variable(self.project, self.function, self.codegen, node, 0x401020)
        with self.assertRaisesRegex(VariableBindingError, "scalar field"):
            scalar_type(None, 32)
        with self.assertRaisesRegex(VariableBindingError, "Select a variable"):
            describe_variable(self.project, self.function, self.codegen, None)

    def test_registers_are_scoped_and_running_binding_rejected(self):
        node = self.variable(SimRegisterVariable(self.arch.registers["eax"][0], 4, name="counter"))
        with self.assertRaisesRegex(VariableBindingError, "no proven live range"):
            describe_variable(self.project, self.function, self.codegen, node, 0x401020)
        binding = VariableBinding("score", "global", 4, "int", "/game", 0x400000, 0x404020)
        runtime = self.runtime()
        runtime.state = "running"
        with self.assertRaisesRegex(VariableBindingError, "Pause"):
            binding.resolve(runtime)

    def test_field_name_selection_recovers_parent_access(self):
        struct = cast("SimStruct", SimStruct({"life": SimTypeInt()}, name="Player").with_arch(self.arch))
        field = CStructField(struct, 0, "life", codegen=self.codegen)
        var = CVariable(SimMemoryVariable(0x404020, 4, name="player"), variable_type=struct, codegen=self.codegen)
        access = CVariableField(var, field, codegen=self.codegen)
        mapping = PositionMapping()
        mapping.add_mapping(0, 6, var)
        mapping.add_mapping(6, 1, access)
        mapping.add_mapping(7, 4, field)
        codegen = SimpleNamespace(map_pos_to_node=mapping, text="player.life")
        self.assertIs(selection_at(codegen, 9), access)
        binding = describe_variable(self.project, self.function, self.codegen, access)
        self.assertEqual(binding.kind, "global")
        self.assertEqual(binding.size, 4)

    def test_instruction_scope_does_not_cross_statement_lines(self):
        nodes = PositionMapping()
        addresses = PositionMapping()
        addresses.add_mapping(0, 4, SimpleNamespace(tags={"ins_addr": 0x401020}))
        codegen = SimpleNamespace(map_pos_to_node=nodes, map_pos_to_addr=addresses, text="a = score;\nother;")
        self.assertEqual(instruction_at(codegen, 7), 0x401020)
        self.assertIsNone(instruction_at(codegen, 12))
        nodes.add_mapping(4, 5, SimpleNamespace(tags={"ins_addr": 0x401024}))
        self.assertEqual(instruction_at(codegen, 7), 0x401024)

    def test_constant_array_element_and_pointer_field(self):
        array = CVariable(
            SimMemoryVariable(0x404020, 16, name="scores"),
            variable_type=SimTypeFixedSizeArray(SimTypeInt(), 4),
            codegen=self.codegen,
        )
        element = CIndexedVariable(array, CConstant(2, SimTypeInt(), codegen=self.codegen), codegen=self.codegen)
        binding = describe_variable(self.project, self.function, self.codegen, element)
        self.assertEqual((binding.offset, binding.size, binding.dereference), (8, 4, False))
        dynamic = CIndexedVariable(array, self.variable(SimStackVariable(-8, 4, name="index")), codegen=self.codegen)
        with self.assertRaisesRegex(VariableBindingError, "constant index"):
            describe_variable(self.project, self.function, self.codegen, dynamic)

        struct = cast(
            "SimStruct", SimStruct({"padding": SimTypeInt(), "life": SimTypeInt()}, name="Player").with_arch(self.arch)
        )
        pointer = CVariable(
            SimMemoryVariable(0x404040, 8, name="player"),
            variable_type=SimTypePointer(struct),
            codegen=self.codegen,
        )
        field = CVariableField(
            pointer, CStructField(struct, 4, "life", codegen=self.codegen), var_is_ptr=True, codegen=self.codegen
        )
        binding = describe_variable(self.project, self.function, self.codegen, field)
        self.assertEqual((binding.offset, binding.size, binding.dereference), (4, 4, True))
        self.assertIn("*(void **)", binding.resolve(self.runtime())["expression"])

        pointers = CVariable(
            SimMemoryVariable(0x404060, 16, name="players"),
            variable_type=SimTypeFixedSizeArray(SimTypePointer(struct), 2),
            codegen=self.codegen,
        )
        selected = CIndexedVariable(pointers, CConstant(1, SimTypeInt(), codegen=self.codegen), codegen=self.codegen)
        member = CVariableField(
            selected, CStructField(struct, 4, "life", codegen=self.codegen), var_is_ptr=True, codegen=self.codegen
        )
        with self.assertRaisesRegex(VariableBindingError, "Indexed pointer chains"):
            describe_variable(self.project, self.function, self.codegen, member)

    def test_same_path_with_different_build_id_is_rejected(self):
        runtime: Any = SimpleNamespace(snapshot=lambda: {"modules": [{"path": "/game", "build_id": "0102"}]})
        verify_module_identity(runtime, "/game", b"\x01\x02")
        with self.assertRaisesRegex(VariableBindingError, "build ID"):
            verify_module_identity(runtime, "/game", b"\x03\x04")


if __name__ == "__main__":
    unittest.main()
