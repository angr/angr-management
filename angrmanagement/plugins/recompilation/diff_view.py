from typing import Optional

from angrmanagement.ui.views.disassembly_view import DisassemblyView


class DiffDisassemblyView(DisassemblyView):
    """
    A Disassembly View for a binary being Diffed. Should never try to synchronize normally since
    it will almost certainly have different addresses
    """

    def on_synchronized_cursor_address_changed(self):
        assert not self._processing_synchronized_cursor_update
        self._processing_synchronized_cursor_update = True
        try:
            if self.sync_state.cursor_address is not None:
                self.instance.recompilation_plugin.syncronize_with_original_disassembly_view()
        finally:
            self._processing_synchronized_cursor_update = False

    def set_synchronized_cursor_address(self, address: Optional[int]):
        pass
