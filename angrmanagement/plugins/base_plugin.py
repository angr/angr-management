import logging

from PySide2 import QtCore

from .plugin_manager import PluginManager

_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)


class BasePlugin(QtCore.QThread):
    _plugin_manager = None

    # TODO: defaults should be read from config file... eventually
    def __init__(self, plugin_manager, workspace):
        QtCore.QThread.__init__(self)

        self._plugin_manager = plugin_manager
        self._workspace = workspace
        self._autostart = False
        _l.info("Loaded {}".format(self.__class__.__name__))

    def register_callbacks(self):
        self._workspace.set_cb_function_backcolor(self.func_back_color)
        self._workspace.set_cb_insn_backcolor(self.insn_backcolor)

    def register_other(self):
        pass

    def autostart(self):
        if self._autostart:
            self.start()

    def teardown(self):
        self.exit(0)

    def run(self):
        raise NotImplementedError("run() must be implemented in derived class!")

    #
    # Callbacks
    #

    def insn_backcolor(self, addr, selected):
        return None, None, None

    def func_back_color(self, func):
        return None, None, None


PluginManager.register_default('base', BasePlugin)
