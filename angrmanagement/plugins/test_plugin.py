from . import PluginManager
from .base_plugin import BasePlugin

# For type hints
from ..ui.menus.disasm_insn_context_menu import DisasmInsnContextMenu


class TestPlugin(BasePlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bookmarks = []

    def insn_backcolor(self, addr):
        return 0xd6, 0xff, 0xd6

    def register_other(self):
        self._workspace.add_disasm_insn_ctx_menu_entry('Bookmark', self.on_ctx_menu_bookmark)

    def on_ctx_menu_bookmark(self, ctx_menu: DisasmInsnContextMenu):
        print("Bookmarking {:#010x}".format(ctx_menu.insn_addr))
        self.bookmarks.append(ctx_menu.insn_addr)


# Uncomment this line to override BasePlugin and see the extras
PluginManager.register_default('test', TestPlugin)
