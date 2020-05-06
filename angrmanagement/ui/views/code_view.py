
from PySide2.QtWidgets import QHBoxLayout, QTextEdit, QMainWindow, QDockWidget
from PySide2.QtGui import QTextCursor
from PySide2.QtCore import Qt

from angr.analyses.decompiler.structured_codegen import CFunctionCall

from ..widgets.qccode_edit import QCCodeEdit
from ..widgets.qdecomp_options import QDecompilationOptions
from ..documents import QCodeDocument
from .view import BaseView


class CodeView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('pseudocode', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Pseudocode'

        self._function = None

        self._codeedit = None
        self._textedit: QCCodeEdit = None
        self._doc = None  # type:QCodeDocument
        self._options = None  # type:QDecompilationOptions

        self._init_widgets()

        self._textedit.cursorPositionChanged.connect(self._on_cursor_position_changed)
        self._textedit.selectionChanged.connect(self._on_cursor_position_changed)
        self._textedit.mouse_double_clicked.connect(self._on_mouse_doubleclicked)

    def reload(self):
        if self.workspace.instance.project is None:
            return
        self._options.reload(force=True)

    def decompile(self):

        if self._function is None:
            return

        d = self.workspace.instance.project.analyses.Decompiler(
            self._function,
            cfg=self.workspace.instance.cfg,
            options=self._options.option_and_values,
            optimization_passes=self._options.selected_passes,
            # kb=dec_kb
            )
        self._doc = QCodeDocument(d.codegen)
        self._textedit.setDocument(self._doc)

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
        self.decompile()

    #
    # Public methods
    #

    def highlight_chunks(self, chunks):
        extra_selections = [ ]
        for start, end in chunks:
            sel = QTextEdit.ExtraSelection()
            sel.cursor = self._textedit.textCursor()
            sel.cursor.setPosition(start)
            sel.cursor.setPosition(end, QTextCursor.KeepAnchor)
            sel.format.setBackground(Qt.yellow)
            extra_selections.append(sel)
        self._textedit.setExtraSelections(extra_selections)

    #
    # Event callbacks
    #

    def _on_cursor_position_changed(self):
        if self._doc is None:
            return

        cursor = self._textedit.textCursor()
        pos = cursor.position()
        selected_node = self._doc.get_node_at_position(pos)
        if selected_node is not None:
            # find all related text chunks and highlight them all
            chunks = self._doc.find_related_text_chunks(selected_node)
            # highlight these chunks
            self.highlight_chunks(chunks)
        else:
            self.highlight_chunks([ ])

    def _on_mouse_doubleclicked(self):
        if self._doc is None:
            return

        cursor = self._textedit.textCursor()
        pos = cursor.position()
        selected_node = self._doc.get_node_at_position(pos)
        if selected_node is not None:
            if isinstance(selected_node, CFunctionCall):
                # decompile this new function
                if selected_node.callee_func is not None:
                    self.workspace.decompile_function(selected_node.callee_func, view=self)

    #
    # Private methods
    #

    def _init_widgets(self):

        window = QMainWindow()
        window.setWindowFlags(Qt.Widget)

        # pseudo code text box
        self._textedit = QCCodeEdit(self)
        self._textedit.setTextInteractionFlags(Qt.TextSelectableByKeyboard | Qt.TextSelectableByMouse)
        self._textedit.setLineWrapMode(QCCodeEdit.NoWrap)
        textedit_dock = QDockWidget('Code', self._textedit)
        window.setCentralWidget(textedit_dock)
        textedit_dock.setWidget(self._textedit)

        # decompilation
        self._options = QDecompilationOptions(self, self.workspace.instance, options=None)
        options_dock = QDockWidget('Decompilation Options', self._options)
        window.addDockWidget(Qt.RightDockWidgetArea, options_dock)
        options_dock.setWidget(self._options)

        layout = QHBoxLayout()
        layout.addWidget(window)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)
