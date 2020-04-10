
import os
import sys
import subprocess
import pathlib

from PySide2.QtCore import QSettings

from ..utils.env import app_path


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
            return False, None

    def is_url_scheme_supported(self):
        return sys.platform.startswith("win") or sys.platform.startswith("linux")

    #
    # Utils
    #

    @staticmethod
    def _angr_desktop_path():
        home_dir = os.path.expanduser("~")
        p = os.path.join(home_dir, ".local", "share", "applications", "angr.desktop")
        return p

    #
    # Windows
    #

    def _register_url_scheme_windows(self):

        app_path_ = app_path(pythonw=True)

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
        reg.setValue("Default", app_path_ + ' -u "%1"')
        reg.endGroup()
        reg.endGroup()
        reg.endGroup()

    def _unregister_url_scheme_windows(self):

        reg_path = self.WIN_REG_PATH.format(self.URL_SCHEME)
        reg = QSettings(reg_path, QSettings.NativeFormat)

        reg.remove("")

    def _is_url_scheme_registered_windows(self):

        reg_path = self.WIN_REG_PATH.format(self.URL_SCHEME)
        reg = QSettings(reg_path, QSettings.NativeFormat)

        if reg.contains("Default"):
            reg.beginGroup("shell")
            reg.beginGroup("open")
            reg.beginGroup("command")
            if reg.contains("Default"):
                return True, reg.value("Default")
        return False, None

    #
    # Linux
    #

    def _register_url_scheme_linux(self):

        cmd_0 = ["xdg-mime", "default", "angr.desktop", "x-scheme-handler/{url_scheme}".format(url_scheme=self.URL_SCHEME)]

        # test if xdg-mime is available
        retcode = subprocess.call(["xdg-mime"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if retcode != 1:
            raise FileNotFoundError("xdg-mime is not installed.")
        retcode = subprocess.call(["xdg-mime", "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if retcode != 0:
            raise FileNotFoundError("xdg-mime is not installed.")

        # extract angr.desktop
        angr_desktop = """[Desktop Entry]
Comment=angr management
Exec={app_path} -u %U
Hidden=true
Name=angr management
Terminal=false
MimeType=x-scheme-handler/{url_scheme};
Type=Application
"""
        angr_desktop_path = self._angr_desktop_path()
        angr_desktop_base = os.path.dirname(angr_desktop_path)
        pathlib.Path(angr_desktop_base).mkdir(parents=True, exist_ok=True)
        with open(angr_desktop_path, "w") as f:
            f.write(
                angr_desktop.format(app_path=app_path(), url_scheme=self.URL_SCHEME)
            )

        # register the scheme
        retcode = subprocess.call(cmd_0)
        if retcode != 0:
            raise ValueError("Failed to setup the URL scheme. Command \"%s\" failed." % " ".join(cmd_0))

    def _unregister_url_scheme_linux(self):

        angr_desktop_path = self._angr_desktop_path()
        if os.path.isfile(angr_desktop_path):
            os.unlink(angr_desktop_path)

    def _is_url_scheme_registered_linux(self):

        # angr.desktop
        angr_desktop_path = self._angr_desktop_path()
        if not os.path.isfile(angr_desktop_path):
            return False, None

        # is xdg-mime available
        retcode = subprocess.call(["xdg-mime"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if retcode != 1:
            return False, None

        # xdg-mine query
        proc = subprocess.Popen(["xdg-mime", "query", "default",
            "x-scheme-handler/{url_scheme}".format(url_scheme=self.URL_SCHEME)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = proc.communicate()
        if not stdout:
            return False, None

        # Load Exec=
        with open(angr_desktop_path, "r") as f:
            data = f.read()
        lines = data.split("\n")
        cmdline = None
        for l in lines:
            if l.startswith("Exec="):
                cmdline = l[5:]
                break
        if cmdline is None:
            return False, None
        return True, cmdline
