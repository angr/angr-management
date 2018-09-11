from PySide2.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy
from PySide2.QtGui import QPainter
from PySide2.QtCore import QSize, Qt

import claripy

from ...config import Conf


class QASTViewer(QFrame):
    def __init__(self, ast, workspace=None, custom_painting=False, display_size=True, byte_format=None, parent=None):
        super(QASTViewer, self).__init__(parent)

        # configs
        self._custom_painting = custom_painting
        self._ast = ast
        self._display_size = display_size
        self._byte_format = byte_format

        # string representations for display
        self._size_str = None
        self._ast_str = None

        # properties that are only used in custom painting mode
        self._x = None
        self._y = None
        self._width = None
        self._height = None

        # widgets. only used in normal painting mode
        self._size_label = None
        self._ast_label = None

        self.setFrameShape(QFrame.NoFrame)
        self.setLineWidth(0)

        # workspace backref
        self.workspace = workspace

        if not self._custom_painting:
            self._init_widgets()
        else:
            self.reload()

    def mouseDoubleClickEvent(self, event):
        if self._ast is not None and not self._ast.symbolic:
            self.workspace.viz(self._ast._model_concrete.value)

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

    @property
    def x(self):
        if not self._custom_painting:
            raise ValueError('QASTViewer does not have a size when custom painting is disabled.')
        return self._x

    @x.setter
    def x(self, v):
        if not self._custom_painting:
            raise ValueError('QASTViewer does not have a size when custom painting is disabled.')
        self._x = v

    @property
    def y(self):
        if not self._custom_painting:
            raise ValueError('QASTViewer does not have a size when custom painting is disabled.')
        return self._y

    @y.setter
    def y(self, v):
        if not self._custom_painting:
            raise ValueError('QASTViewer does not have a size when custom painting is disabled.')
        self._y = v

    @property
    def width(self):
        if not self._custom_painting:
            return super(QASTViewer, self).width()
        else:
            return self._width

    @property
    def height(self):
        if not self._custom_painting:
            return super(QASTViewer, self).height()
        else:
            return self._height

    #
    # Public methods
    #

    def paint(self, painter):
        """

        :param QPainter painter:
        :return:
        """

        if self.x is None or self.y is None:
            # paint() is called before x and y are set
            return

        painter.drawText(self.x, self.y + Conf.symexec_font_ascent, self._ast_str)

    def reload(self):
        # build string representations
        self._build_strings()

        if not self._custom_painting:
            self._reload_widgets()
        else:
            self._determine_size()

    #
    # Private methods
    #

    def _init_widgets(self):

        layout = QHBoxLayout()

        ast_label = QLabel(self)
        self._ast_label = ast_label

        if self._display_size:
            size_label = QLabel(self)
            size_label.setProperty('class', 'ast_viewer_size')
            size_label.setAlignment(Qt.AlignRight)
            size_label.setMaximumSize(QSize(24, 65536))
            self._size_label = size_label
            layout.addWidget(self._size_label)

        if self._ast is not None:
            self.reload()

        layout.addWidget(ast_label)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    def _reload_widgets(self):

        if self._ast is None:
            self._ast_label.setText("")
            return

        ast = self._ast

        # set style
        if isinstance(ast, int) or not ast.symbolic:
            self._ast_label.setProperty('class', 'ast_viewer_ast_concrete')
        else:
            self._ast_label.setProperty('class', 'ast_viewer_ast_symbolic')

        # set text
        if self._display_size:
            self._size_label.setText(self._size_str)
        else:
            self._size_label.setText("")

        self._ast_label.setText(self._ast_str)

        # reapply the style
        self._ast_label.style().unpolish(self._ast_label)
        self._ast_label.style().polish(self._ast_label)

    def _build_strings(self):

        if self._ast is None:
            self._ast_label.setText("")
            return

        ast = self._ast

        # set text
        if isinstance(ast, int):
            if self._display_size:
                self._size_str = '[Unknown]'
            format = "%02x" if self._byte_format is None else self._byte_format
            self._ast_str = format % ast
        else:
            # claripy.AST
            if self._display_size:
                self._size_label.setText("[%d]" % (len(ast) // 8))  # in bytes
            if not ast.symbolic:
                format = "%02x" if self._byte_format is None else self._byte_format
                self._ast_str = format % self._ast._model_concrete.value
            else:
                # symbolic
                if isinstance(ast, claripy.ast.BV) and ast.op == 'BVS':
                    var_name = ast.args[0]
                    self._ast_str = var_name
                else:
                    self._ast_str = ast.__repr__(max_depth=1)

    def _determine_size(self):

        self._height = Conf.symexec_font_height
        self._width = Conf.symexec_font_width * len(self._ast_str)
        if self._display_size:
            self._width += Conf.symexec_font_width * len(self._size_str)
