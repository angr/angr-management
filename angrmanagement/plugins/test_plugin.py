import logging

from . import PluginManager
from .base_plugin import BasePlugin

# For type hints
from ..ui.menus.disasm_insn_context_menu import DisasmInsnContextMenu

_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)


class TestPlugin(BasePlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bookmarks = []
        self._autostart = True
        self._should_run = True

    def register_callbacks(self):
        super().register_callbacks()  # Reuse BasePlugin's registrations for insn/func backcolors

        self._workspace.set_cb_label_rename(self.on_label_rename)
        self._workspace.set_cb_set_comment(self.on_set_comment)

    def register_other(self):
        self._workspace.add_disasm_insn_ctx_menu_entry('Bookmark', self.on_ctx_menu_bookmark)

    def run(self):
        while self._should_run:
            self.sleep(5)

    #
    # Callbacks
    #

    def insn_backcolor(self, addr, selected):
        if not selected:
            if addr in self.bookmarks:
                return 0xd6, 0xff, 0xd6  # light green

        return None, None, None

    def func_back_color(self, func):
        if func.name is None or func.name is '':
            return 255, 255, 255
        # TODO - Hack for a bug. See: https://github.com/angr/cle/pull/175. Won't need None check when merged.
        elif func.binary._entry is not None and func.addr == func.binary.entry:
            return 0xe5, 0xfb, 0xff  # light blue
        else:
            return 255, 255, 255

    def on_ctx_menu_bookmark(self, ctx_menu: DisasmInsnContextMenu):
        _l.info("Bookmarking {:#010x}".format(ctx_menu.insn_addr))
        self.bookmarks.append(ctx_menu.insn_addr)
        self._workspace.views_by_category['disassembly'][0].current_graph.viewport().update()

    def on_label_rename(self, addr: int, new_name: str):
        _l.info("Setting label at {:#010x}='{}'".format(addr, new_name))

    def on_set_comment(self, addr: int, txt: str):
        _l.info("User set comment at {:#010x}: '{}'".format(addr, txt))


# Uncomment this line to override BasePlugin and see the extras
PluginManager.register_default('TestPlugin', TestPlugin)
