
import os

from PySide.QtGui import QIcon

from ...config import IMG_LOCATION
from .toolbar import Toolbar, ToolbarAction


class FileToolbar(Toolbar):
    def __init__(self, main_window):
        super(FileToolbar, self).__init__(main_window, 'File')

        print os.path.join(IMG_LOCATION, 'toolbar-file-open.ico')
        self.actions = [
            ToolbarAction(QIcon(os.path.join(IMG_LOCATION, 'toolbar-file-open.ico')),
                          "Open", "Open a new file for analysis",
                          main_window.load_binary,
                          ),
        ]
