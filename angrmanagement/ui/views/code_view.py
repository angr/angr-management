
from PySide2.QtWidgets import QVBoxLayout, QPlainTextEdit
from PySide2.QtCore import Qt

from ..documents import QCodeDocument
from .view import BaseView


class CodeView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('pseudocode', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Pseudocode'

        self._function = None

        self._text_edit = None  # type:QPlainTextEdit
        self._doc = None  # type:QCodeDocument

        self._init_widgets()

    def reload(self):
        d = self.workspace.instance.project.analyses.Decompiler(self._function)
        self._doc = QCodeDocument(d.codegen)
        self._text_edit.setDocument(self._doc)

    #
    # Properties
    #

    @property
    def function(self):
        return self._function

    @function.setter
    def function(self, v):
        if v is self._function:
            return
        self._function = v
        self.reload()

    #
    # Private methods
    #

    def _init_widgets(self):
        self._text_edit = QPlainTextEdit()
        self._text_edit.setTextInteractionFlags(Qt.TextSelectableByKeyboard | Qt.TextSelectableByMouse)
        self._text_edit.setLineWrapMode(QPlainTextEdit.NoWrap)

        layout = QVBoxLayout()
        layout.addWidget(self._text_edit)
        self.setLayout(layout)
