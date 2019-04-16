import logging

from PySide2 import QtCore

from .plugin_manager import PluginManager

_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)


class BasePlugin(QtCore.QThread):
    """
    :cvar bool is_autoenabled: True means the class is instantiated on import. Otherwise, the plugin will
                               simply be noted as 'installed' and the user can load it later
    :cvar bool is_autostart: True means the instance's thread is started when `autostart()` is called. Otherwise,
                             the user will have to launch it through some action (e.g., a menu, on event, etc).
    :cvar _plugin_manager:  A reference to the `PluginManager` used to load this class
    """
    _plugin_manager = None
    is_autoenabled = True
    is_autostart = False

    # TODO: Allow use of a user-specific config file for is_auto_load/is_auto_start
    # TODO: Do we need to pass both plugin_mgr and workspace? Each has a ref to the other (for now?)
    def __init__(self, plugin_manager, workspace):
        """
        Initializes (enables) a plugin. A plugin that has been instantiated is considered enabled; otherwise, disabled.

        :param plugin_manager:
        :param workspace:
        """
        QtCore.QThread.__init__(self)

        self._plugin_manager = plugin_manager
        self._workspace = workspace
        self._thread_should_run = False
        _l.info("Loaded {}".format(self.__class__.__name__))

    def register_callbacks(self):
        pass

    def register_other(self):
        pass

    def autostart(self):
        """
        If `is_autostart` is True, starts the plugin's thread.
        Called by PluginManager for every installed plugin at startup or when the user enables a plugin.
        """
        if self.is_autostart:
            self.start()

    def sync_stop_thread(self):
        """
        Tells the plugin's thread to stop running, whenever it feels like getting around to that.
        """
        self._thread_should_run = False

    def run(self):
        """
        Derived from `QtCore.QThread`, to be implemented in any derived class that needs
        to be constantly running in the background for UI updates, analyses, etc.

        This is where you define/call your thread's loop.
        """
        raise NotImplementedError("run() must be implemented in derived class!")

    def on_disable(self):
        """
        Gives the plugin a chance to cleanup/save or prompt the user for confirmation
        prior to actually unloading. This should not be called until after any threads
        have been stopped.

        The plugin should remove all callbacks and menus, and disable all functionality
        when this function is called.

        NOTE: Don't log here. By the time the log message goes through, it's likely the
              logger will have been destroyed so Python will throw exceptions.
        """
        pass

    @classmethod
    def get_display_name(cls: 'BasePlugin'):
        return getattr(cls, 'DISPLAY_NAME', cls.__name__)

    #
    # Callbacks
    #

    def insn_backcolor(self, addr, selected):
        return None, None, None

    def func_back_color(self, func):
        return None, None, None

