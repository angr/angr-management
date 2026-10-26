from __future__ import annotations

import unittest
from itertools import count
from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen.base import PositionMapping
from angr.analyses.decompiler.structured_codegen.c import CClosingObject, CConstant, CIndexedVariable, CVariable
from angr.sim_type import SimTypeFixedSizeArray, SimTypeInt
from angr.sim_variable import SimMemoryVariable
from common import create_qapp

from angrmanagement.ui.documents.qcodedocument import QCodeDocument


class TestQCodeDocument(unittest.TestCase):
    """Keep expression selection and bracket pairing compatible across renderer owners."""

    def test_array_brackets_highlight_for_both_owner_types(self):
        app = create_qapp()
        self.assertIsNotNone(app)
        codegen = SimpleNamespace(
            text="items[1]",
            am_none=False,
            next_ident=lambda name: name,
            next_node_idx=count().__next__,
            project=SimpleNamespace(arch=archinfo.ArchAMD64()),
        )
        variable = CVariable(
            SimMemoryVariable(0x404000, 16, name="items"),
            variable_type=SimTypeFixedSizeArray(SimTypeInt(), 4),
            codegen=codegen,
        )
        index = CConstant(1, SimTypeInt(), codegen=codegen)
        access = CIndexedVariable(variable, index, codegen=codegen)
        for owner in (CClosingObject("["), access):
            with self.subTest(owner=type(owner).__name__):
                mapping = PositionMapping()
                mapping.add_mapping(0, 5, variable)
                mapping.add_mapping(5, 1, owner)
                mapping.add_mapping(6, 1, index)
                mapping.add_mapping(7, 1, owner)
                codegen.map_pos_to_node = mapping
                codegen.map_ast_to_pos = {variable.variable: {0}, index.value: {6}, owner: {5, 7}}
                document = QCodeDocument(codegen)
                for position in (5, 7):
                    selected = document.get_node_at_position(position)
                    self.assertIs(selected, owner)
                    chunks = document.find_related_text_chunks(selected)
                    assert chunks is not None
                    self.assertCountEqual(chunks, [(5, 6), (7, 8)])
                self.assertIs(document.get_node_at_position(0), variable)
                self.assertEqual(document.find_related_text_chunks(variable), [(0, 5)])
                self.assertIs(document.get_node_at_position(6), index)
                self.assertEqual(document.find_related_text_chunks(index), [(6, 7)])


if __name__ == "__main__":
    unittest.main()
