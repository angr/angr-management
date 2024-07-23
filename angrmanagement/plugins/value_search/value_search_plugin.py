from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

from angrmanagement.plugins import BasePlugin

from .search_view import SearchView

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace

logger = logging.getLogger(__name__)


class ValueSearch(BasePlugin):
    """
    Plugin to search for values in the binary.
    """

    def __init__(self, workspace: Workspace) -> None:
        super().__init__(workspace)

        self._endness_encoding = None
        self._create_search_view()

    def _find_endness_encoding(self) -> None:
        endness = self.workspace.main_instance.project.arch.memory_endness
        self._endness_encoding = ">" if endness.endswith("BE") else "<"

    #
    # UI Callback Handlers
    #

    def handle_click_menu(self, idx: int) -> None:
        pass

    def color_insn(self, addr: int, selected, disasm_view) -> None:
        pass

    def teardown(self) -> None:
        self._destroy_search_view()

    def _create_search_view(self) -> None:
        self.search_view = SearchView(self, self.workspace, "center", self.workspace.main_instance)
        self.workspace.add_view(self.search_view)

    def _destroy_search_view(self) -> None:
        self.workspace.remove_view(self.search_view)

    #
    # helpers
    #

    def search_in_code(self, value: bytes):
        imms = []
        for func in self.workspace.main_instance.kb.functions.values():
            for block in func.blocks:
                for insn in block.capstone.insns:
                    if hasattr(insn, "operands"):
                        for op in insn.operands:
                            if op.type == 2:
                                imm = self._int_to_bytes(op.imm, strip_zeros=True)
                                if imm == value:
                                    imms.append(insn.address)
        return imms

    def search_by_bytes(self, value: bytes, alignment: int):
        if value is None:
            return []

        addrs = self.workspace.main_instance.project.loader.memory.find(value)
        if alignment <= 1:
            return list(addrs)
        return [addr for addr in addrs if addr % alignment == 0]

    def _float_to_bytes(self, f_value: float):
        if self._endness_encoding is None:
            self._find_endness_encoding()

        try:
            enc_value = struct.pack(f"{self._endness_encoding}f", f_value)
        except struct.error:
            enc_value = None

        return enc_value

    def _double_to_bytes(self, f_value: float):
        if self._endness_encoding is None:
            self._find_endness_encoding()

        try:
            enc_value = struct.pack(f"{self._endness_encoding}d", f_value)
        except struct.error:
            enc_value = None

        return enc_value

    def _int_to_bytes(self, i_value: int, strip_zeros: bool = False):
        if self._endness_encoding is None:
            self._find_endness_encoding()

        try:
            enc_value = struct.pack(f"{self._endness_encoding}I", i_value)
        except struct.error:
            enc_value = None

        if enc_value is not None and strip_zeros:
            enc_value = enc_value.lstrip(b"\x00") if self._endness_encoding == ">" else enc_value.rstrip(b"\x00")

        return enc_value

    #
    # callbacks
    #

    def on_search_trigger(self, value: str, type_: str, alignment: int, should_search_code: bool):
        if type_ == "int":
            i_val = int(value, 0)
            value = self._int_to_bytes(i_val)
        elif type_ == "float":
            f_val = float(value)
            value = self._float_to_bytes(f_val)
        elif type_ == "double":
            f_val = float(value)
            value = self._double_to_bytes(f_val)
        elif type_ == "char":
            value = value.encode()
        else:
            value = value.encode().decode("unicode_escape").encode("latin-1")

        if should_search_code:
            return self.search_in_code(value), value
        else:
            return self.search_by_bytes(value, alignment), value
