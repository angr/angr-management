__version__ = "9.2.26"


try:
    # make sure qtpy (which is used in PyQodeNG.core) is using PySide6
    import os
    os.environ['QT_API'] = 'pyside6'
    import qtpy
except ImportError:
    # qtpy is not installed
    pass
