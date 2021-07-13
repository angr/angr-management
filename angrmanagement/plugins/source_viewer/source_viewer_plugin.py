from collections import defaultdict
from sortedcontainers import SortedDict

from PySide2.QtGui import QCursor
from angrmanagement.ui.workspace import Workspace
from PySide2.QtWidgets import QMenu,QVBoxLayout
from PySide2.QtCore import QRect, QSize
from angrmanagement.ui.views import BaseView
from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.views.disassembly_view import DisassemblyView

from pyqodeng.core.api import CodeEdit
from pyqodeng.core.panels import LineNumberPanel, MarkerPanel, Marker
from pyqodeng.core.widgets import SplittableCodeEditTabWidget
from pyqodeng.core.api.panel import Panel
from pyqodeng.core.api.utils import drift_color, TextHelper

from qtpy import QtCore, QtGui
from cle import Loader


class VaildLineNumberPanel(LineNumberPanel):
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
        for top, line, block in self.editor.visible_blocks:
            if line+1 in self._valid_line:
                painter.setPen(pen_selected)
                painter.setFont(bold_font)
            else:
                painter.setPen(pen)
                painter.setFont(font)
            painter.drawText(-3, top, width, height,
                                QtCore.Qt.AlignRight, str(line + 1))


class StatePanel(Panel):
    _state_counter = {}

    def __init__(self, dynamic=False):
        super().__init__(dynamic=dynamic)

    def updateState(self, data: map):
        self._state_counter = data
        self.repaint()

    def sizeHint(self):
        metrics = QtGui.QFontMetricsF(self.editor.font())
        return QSize(30, metrics.height())

    def paintEvent(self, event):
        Panel.paintEvent(self, event)
        if not self.isVisible():
            return
        font = self.editor.font()
        painter = QtGui.QPainter(self)
        painter.setFont(font)
        for top, block_nbr, block in self.editor.visible_blocks:
            if block_nbr+1 in self._state_counter:
                rect = QRect()
                rect.setX(0)
                rect.setY(top)
                rect.setWidth(self.sizeHint().width())
                rect.setHeight(self.sizeHint().height())
                painter.fillRect(rect,QtGui.QColor("green"))
                painter.drawText(rect, QtCore.Qt.AlignRight,str(self._state_counter[block_nbr+1]))
        painter.end()

    def mousePressEvent(self, event):
        line = TextHelper(self.editor).line_nbr_from_position(event.pos().y())
        print("mousePressEvent ",line)


class SourceCodeViewer(CodeEdit):
    viewer = None # type: SourceViewer
    current_line = -1 # type: int

    def __init__(self, parent):
        super().__init__(parent=parent, create_default_actions=False)
        self.setReadOnly(True)
        self._valid_line = None
        self.linenumber_panel = VaildLineNumberPanel()
        self.breakpoint_panel = MarkerPanel()
        self.breakpoint_panel.add_marker_requested.connect(self.add_marker_fn)
        self.breakpoint_panel.edit_marker_requested.connect(self.edit_marker_fn)
        self.breakpoint_panel.remove_marker_requested.connect(self.remove_marker_fn)

        #self.state_panel = MarkerPanel()

        self.panels.append(self.linenumber_panel)
        self.panels.append(self.breakpoint_panel)
        #self.panels.append(self.state_panel)

    def set_valid_line(self, valid_line):
        self.linenumber_panel._valid_line = valid_line
        self._valid_line = valid_line
        self.update()

    def updateState(self, state_counter):
        self.state_panel.updateState(state_counter)

    def add_find(self):
        desc = self.viewer.add_point(self.file.path, self.current_line, "find")
        self.breakpoint_panel.add_marker(Marker(self.current_line-1,"edit-find",desc))

    def add_avoid(self,):
        desc = self.viewer.add_point(self.file.path, self.current_line, "avoid")
        self.breakpoint_panel.add_marker(Marker(self.current_line-1,"edit-delete",desc))

    def add_marker_fn(self, line):
        self.current_line = line + 1
        if self.current_line not in self._valid_line:
            return
        menu = QMenu()
        menu.addAction("Add Find", self.add_find)
        menu.addAction("Add Avoid", self.add_avoid)
        menu.exec_(QCursor.pos())

    def remove_marker_fn(self, line):
        self.current_line = line + 1
        self.viewer.remove_point(self.file.path, self.current_line)
        lst = self.breakpoint_panel.marker_for_line(line)
        for m in lst:
            self.breakpoint_panel.remove_marker(m)

    def edit_marker_fn(self,line):
        self.current_line = line + 1
        menu = QMenu()
        menu.addAction("Edit Condition", self.edit_cond)
        menu.exec_(QCursor.pos())

    def edit_cond(self):
        print("edit_cond")


class SourceCodeViewerTabWidget(SplittableCodeEditTabWidget):
    editors = {mimetype: SourceCodeViewer for mimetype in SourceCodeViewer.mimetypes}
    fallback_editor = SourceCodeViewer
    addr_to_line = None # type: SortedDict
    line_to_addr = None # type: dict
    viewer = None # type: SourceViewer
    tabs = {} # type: dict(str,SourceCodeViewer)

    def __init__(self, parent=None, addr_to_line: SortedDict=None, viewer=None):
        super().__init__(parent=parent)
        self.viewer = viewer
        if addr_to_line is not None:
            self.load(addr_to_line)

    def load(self, addr_to_line: SortedDict):
        self.addr_to_line = addr_to_line # (filename, line.state.line)
        self.line_to_addr = defaultdict(list)
        self.file_list = set()
        for addr,(filename,line) in self.addr_to_line.items():
            self.file_list.add(filename)
            self.line_to_addr[(filename,line)].append(addr)
        for fn in self.file_list:
            editor = self.open_document(fn) #type: SourceCodeViewer
            editor.viewer = self.viewer
            valid_line = set([line for (filename,line) in self.line_to_addr.keys() if filename == fn ])
            editor.set_valid_line(valid_line)
            self.tabs[fn] = editor

    # def create_line_annotations(self, qblock):

    #     if self.current_simgr.am_none():
    #         # If there's no simgr selected at this moment, then there arent' any labels to show? Maybe
    #         return {}

    #     qinsns = qblock.addr_to_insns.values()

    #     items = defaultdict(list)
    #     for qinsn in qinsns:
    #         addr = qinsn.addr
    #         active_states = []
    #         passthrough_count = 0
    #         active_states += self.addr_to_active_states[addr]
    #         passthrough_count += self.passthrough_counts[addr]
    #         if qinsn.insn.mnemonic.opcode_string == "call":
    #             ret_addr = qinsn.insn.addr + qinsn.insn.size
    #             active_states += self.returning_to_here_states[ret_addr]
    #         if len(active_states) > 0:
    #             items[addr].append(QActiveCount(active_states))
    #         if passthrough_count > 0:
    #             items[addr].append(QPassthroughCount(qinsn.addr, passthrough_count))
    #     return items


class SourceViewer(BaseView):
    addr_to_line = None # type: SortedDict
    disasm_view = None # type: DisassemblyView
    main = None # type: SourceCodeViewerTabWidget
    def __init__(self, workspace :Workspace, *args, **kwargs):
        super(SourceViewer, self).__init__(
            "SourceViewer", workspace, *args, **kwargs
        )
        self.caption = "Source Viewer"
        self.workspace = workspace
        self.instance = workspace.instance
        self.disasm_view = self.workspace.view_manager.first_view_in_category("disassembly")
        self.symexec_view = self.workspace.view_manager.first_view_in_category('symexec')
        workspace.instance.project.am_subscribe(self.load_from_proejct)
        self._init_widgets()

    def _init_widgets(self):
        self.main = SourceCodeViewerTabWidget()
        self.main.viewer = self
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.main)
        self.setLayout(main_layout)

    def load_from_proejct(self,**kwargs):
        if self.instance.project.am_none:
            return
        loader = self.instance.project.loader #type: Loader
        if hasattr(loader.main_object,"addr_to_line") and \
                loader.main_object.addr_to_line is not None:
            self.main.load(loader.main_object.addr_to_line)

    def add_point(self,fn,line, typ):
        address_list = self.main.line_to_addr[(fn,line)]

        for addr in address_list:
            if typ == "find":
                self.symexec_view.find_addr_in_exec(addr)
            else:
                self.symexec_view.avoid_addr_in_exec(addr)
        return "\n".join([ ("0x%x" % i) for i in  address_list])

    def remove_point(self,fn,line):
        address_list = self.main.line_to_addr[(fn,line)]
        for addr in address_list:
            self.symexec_view.remove_find_addr_in_exec(addr)
            self.symexec_view.remove_avoid_addr_in_exec(addr)


class SourceViewerPlugin(BasePlugin):
    def __init__(self, workspace):
        super().__init__(workspace)

        #workspace.source_viewer_plugin = types.SimpleNamespace()

        self.source_viewer = SourceViewer(workspace, "center")
        workspace.default_tabs += [self.source_viewer]
        workspace.add_view(
            self.source_viewer,
            self.source_viewer.caption,
            self.source_viewer.category,
        )
