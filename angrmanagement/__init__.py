__version__ = (8, 20, 1, 7)

# Hack used to work around the slow-responsiveness issue with the GUI
# PySide2 5.14.2 solves this problem but it introduces other bugs
# See https://bugreports.qt.io/browse/PYSIDE-803
# TODO: Remove it after PySide2 5.14.3 or 5.15 are released
import sys
sys.setswitchinterval(0.00001)

