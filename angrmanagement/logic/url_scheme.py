
import os
import sys
import subprocess

from PySide2.QtCore import QSettings


class AngrUrlScheme:

    URL_SCHEME = "angr"
    WIN_REG_PATH = "HKEY_CURRENT_USER\\Software\\Classes\\{}"

    """
    Registers and handlers URL schemes to the operating system.
    """

    def register_url_scheme(self):
        if sys.platform.startswith("win"):
            self._register_url_scheme_windows()
        elif sys.platform.startswith("linux"):
            self._register_url_scheme_linux()
        else:
            raise NotImplementedError("We currently do not support registering angr URL scheme on %s." % sys.platform)

    def unregister_url_scheme(self):
        if sys.platform.startswith("win"):
            self._unregister_url_scheme_windows()
        elif sys.platform.startswith("linux"):
            self._unregister_url_scheme_linux()
        else:
            raise NotImplementedError("We currently do not support unregistering angr URL scheme on %s." % sys.platform)

    def is_url_scheme_registered(self):
        if sys.platform.startswith("win"):
            return self._is_url_scheme_registered_windows()
        elif sys.platform.startswith("linux"):
            return self._is_url_scheme_registered_linux()
        else:
            raise NotImplementedError("We currently do not support registering angr URL scheme on %s." % sys.platform)

    #
    # Utils
    #

    def _app_path(self, pythonw=False):
        """
        Return the path of the application.

        - In standalone mode (a PyInstaller module), we return the absolute path to the executable.
        - In development mode, we return the absolute path to the python executable and "-m angr management"

        :return:    A string that represents the path to the application that can be used to run angr management.
        :rtype:     str
        """

        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            # running as a PyInstaller bundle
            return sys.executable
        else:
            # running as a Python package
            python_path = os.path.normpath(sys.executable)
            if sys.platform.startswith("win") and pythonw:
                python_path = python_path.replace("python.exe", "pythonw.exe")
            app_path = python_path + " -m angrmanagement"
            return app_path

    #
    # Windows
    #

    def _register_url_scheme_windows(self):

        app_path = self._app_path(pythonw=True)

        reg_path = self.WIN_REG_PATH.format(self.URL_SCHEME)
        reg = QSettings(reg_path, QSettings.NativeFormat)

        reg.setValue("Default", "angr management")
        reg.setValue("URL Protocol", "")

        # reg.beginGroup("DefaultIcon")
        # reg.setValue("Default", TODO)
        # reg.endGroup()

        reg.beginGroup("shell")
        reg.beginGroup("open")
        reg.beginGroup("command")
        reg.setValue("Default", app_path + ' "%1"')
        reg.endGroup()
        reg.endGroup()
        reg.endGroup()

    def _unregister_url_scheme_windows(self):

        reg_path = self.WIN_REG_PATH.format(self.URL_SCHEME)
        reg = QSettings(reg_path, QSettings.NativeFormat)

        reg.remove()

    def _is_url_scheme_registered_windows(self):

        reg_path = self.WIN_REG_PATH.format(self.URL_SCHEME)
        reg = QSettings(reg_path, QSettings.NativeFormat)

        if reg.contains("Default"):
            if reg.contains("shell\\open\\command\\Default"):
                return True, reg.value("shell\\open\\command\\Default")
        return False, None

    #
    # Linux
    #

    def _register_url_scheme_linux(self):

        cmd_0 = "gconftool-2 -t string -s /desktop/gnome/url-handlers/{url_scheme}/command '{app_path} \"%s\"'".format(
            url_scheme=self.URL_SCHEME,
            app_path=self._app_path(),
        )
        cmd_1 = "gconftool-2 -s /desktop/gnome/url-handlers/{url_scheme}/needs_terminal false -t bool".format(
            url_scheme=self.URL_SCHEME,
        )
        cmd_2 = "gconftool-2 -s /desktop/gnome/url-handlers/{url_scheme}/enabled true -t bool".format(
            url_scheme=self.URL_SCHEME,
        )

        # test if gconftool-2 is available
        retcode = subprocess.call(["gconftool-2"])
        if retcode != 1:
            raise FileNotFoundError("gconftool-2 is not installed.")
        retcode = subprocess.call(["gconftool-2", "-h"])
        if retcode != 0:
            raise FileNotFoundError("gconftool-2 is not installed.")

        # register the scheme
        retcode = subprocess.call(cmd_0)
        if retcode != 0:
            raise ValueError("Failed to setup the URL scheme. Command \"%s\" failed." % cmd_0)
        retcode = subprocess.call(cmd_1)
        if retcode != 0:
            raise ValueError("Failed to setup the URL scheme. Command \"%s\" failed." % cmd_1)
        retcode = subprocess.call(cmd_2)
        if retcode != 0:
            raise ValueError("Failed to setup the URL scheme. Command \"%s\" failed." % cmd_2)

    def _unregister_url_scheme_linux(self):
        raise NotImplementedError()

    def _is_url_scheme_registered_linux(self):
        raise NotImplementedError()
