""" A minimal application using the Qt console-style Jupyter frontend.

This is not a complete console app, as subprocess will not be able to receive
input, there is no real readline support, among other limitations.
"""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

import os
import signal
import sys
from warnings import warn

from packaging.version import parse

# If run on Windows:
#
# 1. Install an exception hook which pops up a message box.
# Pythonw.exe hides the console, so without this the application
# silently fails to load.
#
# We always install this handler, because the expectation is for
# qtconsole to bring up a GUI even if called from the console.
# The old handler is called, so the exception is printed as well.
# If desired, check for pythonw with an additional condition
# (sys.executable.lower().find('pythonw.exe') >= 0).
#
# 2. Set AppUserModelID for Windows 7 and later so that qtconsole
# uses its assigned taskbar icon instead of grabbing the one with
# the same AppUserModelID
#
if os.name == 'nt':
    # 1.
    old_excepthook = sys.excepthook

    # Exclude this from our autogenerated API docs.
    undoc = lambda func: func

    @undoc
    def gui_excepthook(exctype, value, tb):
        try:
            import ctypes, traceback
            MB_ICONERROR = 0x00000010
            title = 'Error starting QtConsole'
            msg = ''.join(traceback.format_exception(exctype, value, tb))
            ctypes.windll.user32.MessageBoxW(0, msg, title, MB_ICONERROR)
        finally:
            # Also call the old exception hook to let it do
            # its thing too.
            old_excepthook(exctype, value, tb)

    sys.excepthook = gui_excepthook

    # 2.
    try:
        from ctypes import windll
        windll.shell32.SetCurrentProcessExplicitAppUserModelID("Jupyter.Qtconsole")
    except AttributeError:
        pass

from qtpy import QtCore, QtGui, QtWidgets, QT_VERSION

from traitlets.config.application import boolean_flag
from traitlets.config.application import catch_config_error
from .jupyter_widget import JupyterWidget
from .rich_jupyter_widget import RichJupyterWidget
from . import styles, __version__
from .mainwindow import MainWindow
from .client import QtKernelClient
from .manager import QtKernelManager
from traitlets import (
    Dict, Unicode, CBool, Any
)

from jupyter_core.application import JupyterApp, base_flags, base_aliases
from jupyter_client.consoleapp import (
        JupyterConsoleApp, app_aliases, app_flags,
    )


from jupyter_client.localinterfaces import is_local_ip


_examples = """
jupyter qtconsole                      # start the qtconsole
"""

#-----------------------------------------------------------------------------
# Aliases and Flags
#-----------------------------------------------------------------------------

# FIXME: workaround bug in jupyter_client < 4.1 excluding base_flags,aliases
flags = dict(base_flags)
qt_flags = {
    'plain' : ({'JupyterQtConsoleApp' : {'plain' : True}},
            "Disable rich text support."),
}
qt_flags.update(boolean_flag(
    'banner', 'JupyterQtConsoleApp.display_banner',
    "Display a banner upon starting the QtConsole.",
    "Don't display a banner upon starting the QtConsole."
))

# and app_flags from the Console Mixin
qt_flags.update(app_flags)
# add frontend flags to the full set
flags.update(qt_flags)

# start with copy of base jupyter aliases
aliases = dict(base_aliases)
qt_aliases = dict(
    style = 'JupyterWidget.syntax_style',
    stylesheet = 'JupyterQtConsoleApp.stylesheet',

    editor = 'JupyterWidget.editor',
    paging = 'ConsoleWidget.paging',
)
# and app_aliases from the Console Mixin
qt_aliases.update(app_aliases)
qt_aliases.update({'gui-completion':'ConsoleWidget.gui_completion'})
# add frontend aliases to the full set
aliases.update(qt_aliases)

# get flags&aliases into sets, and remove a couple that
# shouldn't be scrubbed from backend flags:
qt_aliases = set(qt_aliases.keys())
qt_flags = set(qt_flags.keys())

class JupyterQtConsoleApp(JupyterApp, JupyterConsoleApp):
    name = 'jupyter-qtconsole'
    version = __version__
    description = """
        The Jupyter QtConsole.

        This launches a Console-style application using Qt.  It is not a full
        console, in that launched terminal subprocesses will not be able to accept
        input.

    """
    examples = _examples

    classes = [JupyterWidget] + JupyterConsoleApp.classes
    flags = Dict(flags)
    aliases = Dict(aliases)
    frontend_flags = Any(qt_flags)
    frontend_aliases = Any(qt_aliases)
    kernel_client_class = QtKernelClient
    kernel_manager_class = QtKernelManager

    stylesheet = Unicode('', config=True,
        help="path to a custom CSS stylesheet")

    hide_menubar = CBool(False, config=True,
        help="Start the console window with the menu bar hidden.")

    maximize = CBool(False, config=True,
        help="Start the console window maximized.")

    plain = CBool(False, config=True,
        help="Use a plaintext widget instead of rich text (plain can't print/save).")

    display_banner = CBool(True, config=True,
        help="Whether to display a banner upon starting the QtConsole."
    )

    def _plain_changed(self, name, old, new):
        kind = 'plain' if new else 'rich'
        self.config.ConsoleWidget.kind = kind
        if new:
            self.widget_factory = JupyterWidget
        else:
            self.widget_factory = RichJupyterWidget

    # the factory for creating a widget
    widget_factory = Any(RichJupyterWidget)

    def parse_command_line(self, argv=None):
        super().parse_command_line(argv)
        self.build_kernel_argv(self.extra_args)


    def new_frontend_master(self):
        """ Create and return new frontend attached to new kernel, launched on localhost.
        """
        kernel_manager = self.kernel_manager_class(
                                connection_file=self._new_connection_file(),
                                parent=self,
                                autorestart=True,
        )
        # start the kernel
        kwargs = {}
        # FIXME: remove special treatment of IPython kernels
        if self.kernel_manager.ipykernel:
            kwargs['extra_arguments'] = self.kernel_argv
        kernel_manager.start_kernel(**kwargs)
        kernel_manager.client_factory = self.kernel_client_class
        kernel_client = kernel_manager.client()
        kernel_client.start_channels(shell=True, iopub=True)
        widget = self.widget_factory(config=self.config,
                                     local_kernel=True)
        self.init_colors(widget)
        widget.kernel_manager = kernel_manager
        widget.kernel_client = kernel_client
        widget._existing = False
        widget._may_close = True
        widget._confirm_exit = self.confirm_exit
        widget._display_banner = self.display_banner
        return widget

    def new_frontend_connection(self, connection_file):
        """Create and return a new frontend attached to an existing kernel.

        Parameters
        ----------
        connection_file : str
            The connection_file path this frontend is to connect to
        """
        kernel_client = self.kernel_client_class(
            connection_file=connection_file,
            config=self.config,
        )
        kernel_client.load_connection_file()
        kernel_client.start_channels()
        widget = self.widget_factory(config=self.config,
                                     local_kernel=False)
        self.init_colors(widget)
        widget._existing = True
        widget._may_close = False
        widget._confirm_exit = False
        widget._display_banner = self.display_banner
        widget.kernel_client = kernel_client
        widget.kernel_manager = None
        return widget

    def new_frontend_slave(self, current_widget):
        """Create and return a new frontend attached to an existing kernel.

        Parameters
        ----------
        current_widget : JupyterWidget
            The JupyterWidget whose kernel this frontend is to share
        """
        kernel_client = self.kernel_client_class(
                                connection_file=current_widget.kernel_client.connection_file,
                                config = self.config,
        )
        kernel_client.load_connection_file()
        kernel_client.start_channels()
        widget = self.widget_factory(config=self.config,
                                local_kernel=False)
        self.init_colors(widget)
        widget._existing = True
        widget._may_close = False
        widget._confirm_exit = False
        widget._display_banner = self.display_banner
        widget.kernel_client = kernel_client
        widget.kernel_manager = current_widget.kernel_manager
        return widget

    def init_qt_app(self):
        # separate from qt_elements, because it must run first
        if QtWidgets.QApplication.instance() is None:
            self.app = QtWidgets.QApplication(['jupyter-qtconsole'])
            self.app.setApplicationName('jupyter-qtconsole')
        else:
            self.app = QtWidgets.QApplication.instance()

    def init_qt_elements(self):
        # Create the widget.

        base_path = os.path.abspath(os.path.dirname(__file__))
        icon_path = os.path.join(base_path, 'resources', 'icon', 'JupyterConsole.svg')
        self.app.icon = QtGui.QIcon(icon_path)
        QtWidgets.QApplication.setWindowIcon(self.app.icon)

        ip = self.ip
        local_kernel = (not self.existing) or is_local_ip(ip)
        self.widget = self.widget_factory(config=self.config,
                                        local_kernel=local_kernel)
        self.init_colors(self.widget)
        self.widget._existing = self.existing
        self.widget._may_close = not self.existing
        self.widget._confirm_exit = self.confirm_exit
        self.widget._display_banner = self.display_banner

        self.widget.kernel_manager = self.kernel_manager
        self.widget.kernel_client = self.kernel_client
        self.window = MainWindow(self.app,
                                confirm_exit=self.confirm_exit,
                                new_frontend_factory=self.new_frontend_master,
                                slave_frontend_factory=self.new_frontend_slave,
                                connection_frontend_factory=self.new_frontend_connection,
                                )
        self.window.log = self.log
        self.window.add_tab_with_frontend(self.widget)
        self.window.init_menu_bar()

        # Ignore on OSX, where there is always a menu bar
        if sys.platform != 'darwin' and self.hide_menubar:
            self.window.menuBar().setVisible(False)

        self.window.setWindowTitle('Jupyter QtConsole')

    def init_colors(self, widget):
        """Configure the coloring of the widget"""
        # Note: This will be dramatically simplified when colors
        # are removed from the backend.

        # parse the colors arg down to current known labels
        cfg = self.config
        colors = cfg.ZMQInteractiveShell.colors if 'ZMQInteractiveShell.colors' in cfg else None
        style = cfg.JupyterWidget.syntax_style if 'JupyterWidget.syntax_style' in cfg else None
        sheet = cfg.JupyterWidget.style_sheet if 'JupyterWidget.style_sheet' in cfg else None

        # find the value for colors:
        if colors:
            colors=colors.lower()
            if colors in ('lightbg', 'light'):
                colors='lightbg'
            elif colors in ('dark', 'linux'):
                colors='linux'
            else:
                colors='nocolor'
        elif style:
            if style=='bw':
                colors='nocolor'
            elif styles.dark_style(style):
                colors='linux'
            else:
                colors='lightbg'
        else:
            colors=None

        # Configure the style
        if style:
            widget.style_sheet = styles.sheet_from_template(style, colors)
            widget.syntax_style = style
            widget._syntax_style_changed()
            widget._style_sheet_changed()
        elif colors:
            # use a default dark/light/bw style
            widget.set_default_style(colors=colors)

        if self.stylesheet:
            # we got an explicit stylesheet
            if os.path.isfile(self.stylesheet):
                with open(self.stylesheet) as f:
                    sheet = f.read()
            else:
                raise IOError("Stylesheet %r not found." % self.stylesheet)
        if sheet:
            widget.style_sheet = sheet
            widget._style_sheet_changed()


    def init_signal(self):
        """allow clean shutdown on sigint"""
        signal.signal(signal.SIGINT, lambda sig, frame: self.exit(-2))
        # need a timer, so that QApplication doesn't block until a real
        # Qt event fires (can require mouse movement)
        # timer trick from http://stackoverflow.com/q/4938723/938949
        timer = QtCore.QTimer()
         # Let the interpreter run each 200 ms:
        timer.timeout.connect(lambda: None)
        timer.start(200)
        # hold onto ref, so the timer doesn't get cleaned up
        self._sigint_timer = timer

    def _deprecate_config(self, cfg, old_name, new_name):
        """Warn about deprecated config."""
        if old_name in cfg:
            self.log.warning(
                "Use %s in config, not %s. Outdated config:\n    %s",
                new_name, old_name,
                '\n    '.join(
                    '{name}.{key} = {value!r}'.format(key=key, value=value,
                                                      name=old_name)
                    for key, value in self.config[old_name].items()
                )
            )
            cfg = cfg.copy()
            cfg[new_name].merge(cfg[old_name])
            return cfg

    def _init_asyncio_patch(self):
        """
        Same workaround fix as https://github.com/ipython/ipykernel/pull/456

        Set default asyncio policy to be compatible with tornado
        Tornado 6 (at least) is not compatible with the default
        asyncio implementation on Windows
        Pick the older SelectorEventLoopPolicy on Windows
        if the known-incompatible default policy is in use.
        do this as early as possible to make it a low priority and overrideable
        ref: https://github.com/tornadoweb/tornado/issues/2608
        FIXME: if/when tornado supports the defaults in asyncio,
               remove and bump tornado requirement for py38
        """
        if sys.platform.startswith("win") and sys.version_info >= (3, 8):
            import asyncio
            try:
                from asyncio import (
                    WindowsProactorEventLoopPolicy,
                    WindowsSelectorEventLoopPolicy,
                )
            except ImportError:
                pass
                # not affected
            else:
                if type(asyncio.get_event_loop_policy()) is WindowsProactorEventLoopPolicy:
                    # WindowsProactorEventLoopPolicy is not compatible with tornado 6
                    # fallback to the pre-3.8 default of Selector
                    asyncio.set_event_loop_policy(WindowsSelectorEventLoopPolicy())

    @catch_config_error
    def initialize(self, argv=None):
        # Fixes launching issues with Big Sur
        # https://bugreports.qt.io/browse/QTBUG-87014, fixed in qt 5.15.2
        if sys.platform == 'darwin':
            v_5_15_2 = parse('5.15.2')
            v_current = parse(QT_VERSION)
            if v_current < v_5_15_2:
                os.environ['QT_MAC_WANTS_LAYER'] = '1'
        self._init_asyncio_patch()
        self.init_qt_app()
        super().initialize(argv)
        if self._dispatching:
            return
        # handle deprecated renames
        for old_name, new_name in [
            ('IPythonQtConsoleApp', 'JupyterQtConsole'),
            ('IPythonWidget', 'JupyterWidget'),
            ('RichIPythonWidget', 'RichJupyterWidget'),
        ]:
            cfg = self._deprecate_config(self.config, old_name, new_name)
            if cfg:
                self.update_config(cfg)
        JupyterConsoleApp.initialize(self,argv)
        self.init_qt_elements()
        self.init_signal()

    def start(self):
        super().start()

        # draw the window
        if self.maximize:
            self.window.showMaximized()
        else:
            self.window.show()
        self.window.raise_()

        # Start the application main loop.
        self.app.exec_()


class IPythonQtConsoleApp(JupyterQtConsoleApp):
    def __init__(self, *a, **kw):
        warn("IPythonQtConsoleApp is deprecated; use JupyterQtConsoleApp",
             DeprecationWarning)
        super().__init__(*a, **kw)


# -----------------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------------

def main():
    JupyterQtConsoleApp.launch_instance()


if __name__ == '__main__':
    main()
