import logging
import struct

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.views.disassembly_view import DisassemblyView

logger = logging.getLogger(__name__)


class ValueSearch(BasePlugin):
    def __init__(self, workspace):
        super().__init__(workspace)

        endness = self.workspace.main_instance.project.arch.memory_endness
        self._endness_encoding = "<" if endness.endswith("BE") else ">"

        self._create_search_view()

    #
    # UI Callback Handlers
    #

    def handle_click_menu(self, idx):
        pass

    def color_insn(self, addr, selected, disasm_view):
        pass

    def teardown(self):
        self._destroy_search_view()

    def _create_search_view(self):
        self.search_view = DisassemblyView(self.workspace, self.workspace.main_instance, "center")
        self.workspace.add_view(self.search_view)

    def _destroy_search_view(self):
        self.workspace.remove_view(self.search_view)

    #
    # helpers
    #

    def search_by_bytes(self, value: bytes):
        if value is None:
            return []

        return list(self.workspace.main_instance.project.loader.memory.find(value))

    def _float_to_bytes(self, f_value: float):
        try:
            enc_value = struct.pack(f"{self._endness_encoding}f", f_value)
        except:
            enc_value = None

        return enc_value

    def _int_to_bytes(self, i_value: int):
        try:
            enc_value = struct.pack(f"{self._endness_encoding}I", i_value)
        except:
            enc_value = None

        return enc_value

    #
    # callbacks
    #

    def on_search_trigger(self, value: str, type_: str):
        if type_ == "int":
            i_val = int(value, 0)
            value = self._int_to_bytes(i_val)
        elif type_ == "float":
            f_val = float(value)
            value = self._float_to_bytes(f_val)
        else:
            value = value.encode()

        return self.search_by_bytes(value)


