from typing import Union, List

import sys
import os


def is_pyinstaller() -> bool:
    """
    Detect if we are currently running as a PyInstaller-packaged program.
    :return:    True if we are running as a PyInstaller-packaged program. False if we are running in Python directly
                (e.g., development mode).
    """
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')


def app_path(pythonw=None, as_list=False) -> Union[str,List[str]]:
    """
    Return the path of the application.

    - In standalone mode (a PyInstaller module), we return the absolute path to the executable.
    - In development mode, we return the absolute path to the python executable and "-m angr management"

    :return:    A string that represents the path to the application that can be used to run angr management.
    :rtype:     str|list
    """

    if is_pyinstaller():
        # running as a PyInstaller bundle
        if as_list:
            return [sys.executable]
        return sys.executable
    else:
        # running as a Python package
        python_path = os.path.normpath(sys.executable)
        if sys.platform.startswith("win"):
            # if pythonw is None, we don't do anything
            if pythonw is True:
                python_path = python_path.replace("python.exe", "pythonw.exe")
            elif pythonw is False:
                python_path = python_path.replace("pythonw.exe", "python.exe")
        if as_list:
            return [python_path, "-m", "angrmanagement"]
        else:
            if " " in python_path:
                python_path = '"%s"' % python_path
            app_path = python_path + " -m angrmanagement"
            return app_path


def app_root() -> str:
    """
    Return the path of the application.

    - In standalone mode (a PyInstaller module), we return the absolute path of the directory where the executable is.
    - In development mode, we return the absolute path to the directory where the angr management package is.

    :return:    A string that represents the path to the application that can be used to run angr management.
    """

    if is_pyinstaller():
        # running as a PyInstaller bundle
        return os.path.dirname(sys.executable)
    else:
        # running as a Python package
        return os.path.normpath(os.path.join(os.path.abspath(__file__), "..", ".."))
