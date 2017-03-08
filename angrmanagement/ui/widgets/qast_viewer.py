
from PySide.QtGui import QFrame, QHBoxLayout, QLabel, QSizePolicy
from PySide.QtCore import QSize
from PySide.QtCore import Qt

import claripy


class QASTViewer(QFrame):
    def __init__(self, ast, parent=None):
        super(QASTViewer, self).__init__(parent)

        self._ast = ast

        self._size_label = None
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
        self.reload()

    #
    # Public methods
    #

    def reload(self):
        if self._ast is None:
            return

        ast = self._ast

        # set style
        if isinstance(ast, (int, long)) or not ast.symbolic:
            self._ast_label.setProperty('class', 'ast_viewer_ast_concrete')
        else:
            self._ast_label.setProperty('class', 'ast_viewer_ast_symbolic')

        # set text
        if isinstance(ast, (int, long)):
            self._size_label.setText('pUnknown]')
            self._ast_label.setText("%#x" % ast)
        else:
            # claripy.AST
            self._size_label.setText("[%d]" % (len(ast) / 8))  # in bytes
            if not ast.symbolic:
                self._ast_label.setText("%#x" % self._ast._model_concrete.value)
            else:
                # symbolic
                if isinstance(ast, claripy.ast.BV) and ast.op == 'BVS':
                    var_name = ast.args[0]
                    self._ast_label.setText(var_name)
                else:
                    self._ast_label.setText(ast.__repr__(max_depth=1))

        # reapply the style
        self._ast_label.style().unpolish(self._ast_label)
        self._ast_label.style().polish(self._ast_label)

    #
    # Private methods
    #

    def _init_widgets(self):

        layout = QHBoxLayout()

        size_label = QLabel()
        size_label.setProperty('class', 'ast_viewer_size')
        size_label.setAlignment(Qt.AlignRight)
        size_label.setMaximumSize(QSize(24, 65536))
        self._size_label = size_label

        ast_label = QLabel()
        self._ast_label = ast_label
        if self._ast is not None:
            self.reload()

        layout.addWidget(self._size_label)
        layout.addWidget(ast_label)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)
