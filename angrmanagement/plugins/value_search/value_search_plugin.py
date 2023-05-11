import logging

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.views.disassembly_view import DisassemblyView

logger = logging.getLogger(__name__)


class ValueSearch(BasePlugin):
    def __init__(self, workspace):
        super().__init__(workspace)
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
