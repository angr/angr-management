from collections import defaultdict
from typing import TYPE_CHECKING
from sortedcontainers import SortedDict

from PySide2.QtGui import QCursor
from PySide2.QtWidgets import QInputDialog, QLineEdit, QMenu, QPlainTextEdit, QStyle, QVBoxLayout
from PySide2.QtCore import QEvent, Qt

from pyqodeng.core.api import CodeEdit
from pyqodeng.core.panels import LineNumberPanel, MarkerPanel, Marker
from pyqodeng.core.widgets import SplittableCodeEditTabWidget
from pyqodeng.core.api.panel import Panel
from pyqodeng.core.api.utils import drift_color

from qtpy import QtCore, QtGui
from cle import Loader

from angrmanagement.ui.widgets.qccode_edit import ColorSchemeIDA
from angrmanagement.ui.views import BaseView
from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.workspace import Workspace
from angrmanagement.ui.widgets.qccode_highlighter import QCCodeHighlighter

if TYPE_CHECKING:
    from angrmanagement.ui.views.disassembly_view import DisassemblyView
    from angrmanagement.ui.views.symexec_view import SymexecView


class VaildLineNumberPanel(LineNumberPanel):
    """
    The color of line numbers indicates if any address associated with this line.
    The vaild lineno are black, which means we could set a breakpoint on it and
    the invaild are grey.
    """

    def __init__(self, valid_line=None):
        super().__init__()
        self._valid_line = valid_line or set()

    def paintEvent(self, event):
        # Paints the line numbers
        self._line_color_u = drift_color(self._background_brush.color(), 250)
        self._line_color_s = drift_color(self._background_brush.color(), 280)
        Panel.paintEvent(self, event)
        if not self.isVisible():
            return
        painter = QtGui.QPainter(self)
        # get style options (font, size)
        width = self.width()
        height = self.editor.fontMetrics().height()
        font = self.editor.font()
        bold_font = self.editor.font()
        bold_font.setBold(True)
        pen = QtGui.QPen(self._line_color_u)
        pen_selected = QtGui.QPen(self._line_color_s)
        painter.setFont(font)
        # draw every visible blocks
        for top, line, _block in self.editor.visible_blocks:
            if line+1 in self._valid_line:
                painter.setPen(pen_selected)
                painter.setFont(bold_font)
            else:
                painter.setPen(pen)
                painter.setFont(font)
            painter.drawText(-3, top, width, height,
                             QtCore.Qt.AlignRight, str(line + 1))


class SourceCodeViewer(CodeEdit):
    """
    CodeEdit for one source code file.
    Used by SourceCodeViewerTabWidget.
    """
    viewer = None  # type: SourceViewer
    current_line = -1  # type: int

    def __init__(self, parent):
        super().__init__(parent=parent, create_default_actions=False)

        self._valid_line = None
        self.linenumber_panel = VaildLineNumberPanel()
        self.breakpoint_panel = MarkerPanel()
        self.breakpoint_panel.add_marker_requested.connect(self.add_marker_fn)
        self.breakpoint_panel.edit_marker_requested.connect(
            self.edit_marker_fn)
        self.breakpoint_panel.remove_marker_requested.connect(
            self.remove_marker_fn)

        #self.state_panel = MarkerPanel()

        self.panels.append(self.linenumber_panel)
        self.panels.append(self.breakpoint_panel)
        # self.panels.append(self.state_panel)

    def set_valid_line(self, valid_line):
        self.linenumber_panel._valid_line = valid_line
        self._valid_line = valid_line
        self.update()

    def updateState(self, state_counter):
        self.state_panel.updateState(state_counter)

    def add_find(self):
        icon = self.style().standardIcon(QStyle.SP_FileDialogContentsView)
        desc = self.viewer.add_point(self.file.path, self.current_line, "find")
        self.breakpoint_panel.add_marker(
            Marker(self.current_line-1, icon, desc))

    def add_avoid(self):
        icon = self.style().standardIcon(QStyle.SP_BrowserStop)
        desc = self.viewer.add_point(
            self.file.path, self.current_line, "avoid")
        self.breakpoint_panel.add_marker(
            Marker(self.current_line-1, icon, desc))

    def jump_to(self,addr):
        self.viewer.workspace.jump_to(addr)

    def add_marker_fn(self, line):
        self.current_line = line + 1
        if self.current_line not in self._valid_line:
            return
        menu = QMenu()
        menu.addAction("Add Find", self.add_find)
        menu.addAction("Add Avoid", self.add_avoid)
        address_list = self.viewer.main.line_to_addr[(self.file.path, self.current_line)]
        if address_list:
            jump_menu = menu.addMenu("Jump to")
            for addr in address_list:
                jump_menu.addAction("0x%x" % addr, lambda addr=addr: self.jump_to(addr))
        menu.exec_(QCursor.pos())

    def remove_marker_fn(self, line):
        self.current_line = line + 1
        self.viewer.remove_point(self.file.path, self.current_line)
        lst = self.breakpoint_panel.marker_for_line(line)
        for m in lst:
            self.breakpoint_panel.remove_marker(m)

    def edit_marker_fn(self, line):
        self.current_line = line + 1
        menu = QMenu()
        menu.addAction("Edit Condition", self.edit_cond)
        menu.exec_(QCursor.pos())

    def edit_cond(self):
        pass

    def setHighlighter(self):
        self.modes.append(QCCodeHighlighter(
            self.document(), color_scheme=ColorSchemeIDA()))
        QPlainTextEdit.setReadOnly(self, True)
        self.setTextInteractionFlags(
            Qt.TextSelectableByKeyboard | Qt.TextSelectableByMouse)

    def event(self, event):
        if event.type() == QEvent.KeyPress and event.key() in (Qt.Key_Slash, Qt.Key_Question):
            event.accept()
            self.comment()
            return True

        return super().event(event)

    def comment(self):
        doc = self.document()
        cursor = self.textCursor()
        cursor.clearSelection()
        block = doc.findBlock(cursor.position())
        text = block.text().rsplit("//", 1)
        if len(text) == 1:
            comment = ""
            no_comment = True
        else:
            text, comment = text
            no_comment = False
        new_comment, ok = QInputDialog.getText(
            None, "Comment", "Comment", QLineEdit.Normal, comment)
        if not ok:
            return
        cursor.movePosition(cursor.EndOfLine, cursor.MoveAnchor)
        for _ in range(len(comment)):
            cursor.deletePreviousChar()
        if no_comment:
            cursor.insertText(" // ")
        cursor.insertText(new_comment)
        cursor.block()


class SourceCodeViewerTabWidget(SplittableCodeEditTabWidget):
    """
    CodeEdit for one ELF file.
    It could contain more than one file.
    """
    editors = {
        mimetype: SourceCodeViewer for mimetype in SourceCodeViewer.mimetypes}
    fallback_editor = SourceCodeViewer
    addr_to_line = None  # type: SortedDict
    line_to_addr = None  # type: dict
    viewer = None  # type: SourceViewer
    tabs = {}  # type: dict(str,SourceCodeViewer)

    def __init__(self, parent=None, addr_to_line: SortedDict = None, viewer=None):
        super().__init__(parent=parent)
        self.viewer = viewer
        if addr_to_line is not None:
            self.load(addr_to_line)

    def load(self, addr_to_line: SortedDict):
        self.addr_to_line = addr_to_line  # (filename, line.state.line)
        self.line_to_addr = defaultdict(list)
        self.file_list = set()
        for addr, (filename, line) in self.addr_to_line.items():
            self.file_list.add(filename)
            self.line_to_addr[(filename, line)].append(addr)
        for fn in self.file_list:
            editor = self.open_document(fn)  # type: SourceCodeViewer
            editor.viewer = self.viewer
            editor.setHighlighter()
            valid_line = {
                line for (filename, line) in self.line_to_addr.keys() if filename == fn}
            editor.set_valid_line(valid_line)
            self.tabs[fn] = editor


class SourceViewer(BaseView):
    """
    Main class of the Source Viewer Plugin
    """
    addr_to_line = None  # type: SortedDict

    main = None  # type: SourceCodeViewerTabWidget

    def __init__(self, workspace: Workspace, *args, **kwargs):
        super().__init__("SourceViewer", workspace, *args, **kwargs)
        self.base_caption = "Source Viewer"
        self.workspace = workspace
        self.instance = workspace.instance
        workspace.instance.project.am_subscribe(self.load_from_proejct)
        self._init_widgets()

    @property
    def disasm_view(self) -> 'DisassemblyView':
        return self.workspace.view_manager.first_view_in_category("disassembly")

    @property
    def symexec_view(self) -> 'SymexecView':
        return self.workspace.view_manager.first_view_in_category('symexec')

    def _init_widgets(self):
        self.main = SourceCodeViewerTabWidget()
        self.main.viewer = self
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.main)
        self.setLayout(main_layout)

    def load_from_proejct(self, **kwargs):  # pylint: disable=unused-argument
        if self.instance.project.am_none:
            return
        loader = self.instance.project.loader  # type: Loader
        if hasattr(loader.main_object, "addr_to_line") and \
                loader.main_object.addr_to_line is not None:
            self.main.load(loader.main_object.addr_to_line)

    def add_point(self, fn, line, typ):
        symexec_view = self.symexec_view
        if not symexec_view:
            return ""
        address_list = self.main.line_to_addr[(fn, line)]

        for addr in address_list:
            if typ == "find":
                symexec_view.find_addr_in_exec(addr)
            else:
                symexec_view.avoid_addr_in_exec(addr)
        return "\n".join([("0x%x" % i) for i in address_list])

    def remove_point(self, fn, line):
        symexec_view = self.symexec_view
        if not symexec_view:
            return

        address_list = self.main.line_to_addr[(fn, line)]
        for addr in address_list:
            symexec_view.remove_find_addr_in_exec(addr)
            symexec_view.remove_avoid_addr_in_exec(addr)


class SourceViewerPlugin(BasePlugin):
    """
    Plugin loader
    """

    def __init__(self, workspace):
        super().__init__(workspace)
        self.source_viewer = SourceViewer(workspace, "center")
        workspace.default_tabs += [self.source_viewer]
        workspace.add_view(self.source_viewer)
