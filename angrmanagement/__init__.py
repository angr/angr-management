__version__ = "9.2.5"

# Hack used to work around the slow-responsiveness issue with the GUI
# PySide2 5.14.2 solves this problem but it introduces other bugs
# See https://bugreports.qt.io/browse/PYSIDE-803
try:
    import PySide2
    version = [int(k) for k in PySide2.__version__.split(".")[:4]]
    while len(version) < 4:
        version.append(0)
    version = tuple(version)
    if version < (5, 14, 2, 0):
        import sys
        sys.setswitchinterval(0.00001)
except ImportError:
    pass


try:
    # make sure qtpy (which is used in PyQodeNG.core) is using PySide2
    import os
    os.environ['QT_API'] = 'pyside2'
    import qtpy
except ImportError:
    # qtpy is not installed
    pass
