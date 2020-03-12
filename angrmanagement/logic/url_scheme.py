
import os
import sys

from PySide2.QtCore import QSettings


class AngrUrlScheme:

    URL_SCHEME = "angr"

    """
    Registers and handlers URL schemes to the operating system.
    """

    def register_url_scheme(self):
        self._register_url_scheme_windows()

    def _register_url_scheme_windows(self):

        python_path = os.path.normpath(sys.executable)
        if sys.platform.startswith("win"):
            python_path = python_path.replace("python.exe", "pythonw.exe")
        app_path = python_path + " -m angrmanagement"

        reg_path = "HKEY_CURRENT_USER\\Software\\Classes\\{}".format(self.URL_SCHEME)
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
