import logging

from ..base_plugin import BasePlugin
from ...ui.menus.disasm_insn_context_menu import DisasmInsnContextMenu  # For type hints

_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)


class TestPlugin(BasePlugin):
    DISPLAY_NAME = 'Test Plugin'
    is_autostart = True
    is_autoenabled = False
    __ctx_menu_text = '&Bookmark'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bookmarks = []
        self._thread_should_run = True

    def register_callbacks(self):
        self._workspace.set_cb_function_backcolor(self.func_back_color)
        self._workspace.set_cb_insn_backcolor(self.insn_backcolor)
        self._workspace.set_cb_label_rename(self.on_label_rename)
        self._workspace.set_cb_set_comment(self.on_set_comment)

    def register_other(self):
        self._workspace.add_disasm_insn_ctx_menu_entry(self.__ctx_menu_text, self.on_ctx_menu_bookmark)

    def on_disable(self):
        self._workspace.set_cb_function_backcolor(None)
        self._workspace.set_cb_insn_backcolor(None)
        self._workspace.set_cb_label_rename(None)
        self._workspace.set_cb_set_comment(None)
        self._workspace.remove_disasm_insn_ctx_menu_entry(self.__ctx_menu_text)

    def run(self):
        while self._thread_should_run:
            _l.info("looping")
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
        self._workspace.view_manager.first_view_in_category('disassembly').current_graph.viewport().update()

    def on_label_rename(self, addr: int, new_name: str):
        _l.info("Setting label at {:#010x}='{}'".format(addr, new_name))

    def on_set_comment(self, addr: int, txt: str):
        _l.info("User set comment at {:#010x}: '{}'".format(addr, txt))
