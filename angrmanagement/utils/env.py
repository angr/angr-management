
import sys
import os


def app_path(pythonw=False, as_list=False):
    """
    Return the path of the application.

    - In standalone mode (a PyInstaller module), we return the absolute path to the executable.
    - In development mode, we return the absolute path to the python executable and "-m angr management"

    :return:    A string that represents the path to the application that can be used to run angr management.
    :rtype:     str
    """

    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # running as a PyInstaller bundle
        if as_list:
            return [sys.executable]
        return sys.executable
    else:
        # running as a Python package
        python_path = os.path.normpath(sys.executable)
        if sys.platform.startswith("win") and pythonw:
            python_path = python_path.replace("python.exe", "pythonw.exe")
        if as_list:
            return [python_path, "-m", "angrmanagement"]
        else:
            app_path = python_path + " -m angrmanagement"
            return app_path
