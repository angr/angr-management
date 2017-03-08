
from PySide.QtGui import QFrame, QHBoxLayout, QLabel, QSizePolicy
from PySide.QtCore import Qt


class QASTViewer(QFrame):
    def __init__(self, ast, parent=None):
        super(QASTViewer, self).__init__(parent)

        self._ast = ast

        self._ast_label = None

        self.setFrameShape(QFrame.NoFrame)
        self.setLineWidth(0)

        self._init_widgets()

    #
    # Properties
    #

    @property
    def ast(self):
        return self._ast

    @ast.setter
    def ast(self, v):
        self._ast = v
        self._ast_label.setText(str(self._ast))

    #
    # Private methods
    #

    def _init_widgets(self):

        layout = QHBoxLayout()

        lbl = QLabel()
        self._ast_label = lbl
        if self._ast is not None:
            lbl.setText(str(self._ast))

        layout.addWidget(lbl)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)
