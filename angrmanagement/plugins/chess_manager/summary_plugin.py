import json
import logging
from copy import deepcopy
import os
from typing import Optional, Union

from PySide2.QtGui import QColor
from PySide2.QtWidgets import QFileDialog, QMessageBox

from ...data.object_container import ObjectContainer
from ..base_plugin import BasePlugin
from .summary_view import SummaryView


_l = logging.getLogger(__name__)
# _l.setLevel('DEBUG')


class ChessSummaryPlugin(BasePlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.summary_view = SummaryView(self.workspace)
        self.workspace.add_view(self.summary_view)

    def teardown(self):
        self.summary_view.close()

