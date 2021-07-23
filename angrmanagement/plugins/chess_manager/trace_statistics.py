import logging
import random
from collections import defaultdict

from PySide2.QtGui import QColor
from angr.errors import SimEngineError

l = logging.getLogger(name=__name__)


class TraceFunc:
    """
    Trace and Function class

    """
    def __init__(self, bbl_addr=None, func_name=None, func=None):
        self.bbl_addr = bbl_addr
        self.func_name = func_name
        self.func = func


class TraceStatistics:
    """
    Trace and color / legend record
    """

    BBL_FILL_COLOR = QColor(0, 0xf0, 0xf0, 0xf)
    BBL_BORDER_COLOR = QColor(0, 0xf0, 0xf0)
    BBL_EMPTY_COLOR = QColor("white")

    def __init__(self, workspace, trace, trace_id=None, baddr=None):
        self.workspace = workspace
        self.bbl_addrs = trace
        self.id = trace_id
        self.trace_func = []
        self._func_color = {}
        self.count = None
        self._mark_color = {}
        self._positions = defaultdict(list)
        self.mapped_trace = []

        project = self.workspace.instance.project
        if project.am_none:
            self.project_baddr = None
        else:
            self.project_baddr = project.loader.main_object.mapped_base
        if baddr is None:
            self.runtime_baddr = self.project_baddr
        else:
            self.runtime_baddr = baddr

        self._statistics(self.bbl_addrs)

    def get_func_color(self, func_name):
        if func_name in self._func_color:
            return self._func_color[func_name]
        else:
            color = self._random_color()
            self._func_color[func_name] = color
        return color

    def set_mark_color(self, p, color):
        self._mark_color[p] = color

    def get_mark_color(self, addr, i):
        try:
            mark_index = self._get_position(addr, i)
            mark_color = self._mark_color[mark_index]
        except (IndexError, KeyError) as e:
            l.error(e)
            return self.BBL_EMPTY_COLOR
        return mark_color

    def get_positions(self, addr):
        return self._positions[addr]

    def get_count(self, ins):
        return len(self._positions[ins])

    def get_bbl_from_position(self, position):
        return self.trace_func[position].bbl_addr

    def get_func_name_from_position(self, position):
        return self.trace_func[position].func_name

    def get_func_from_position(self, position):
        return self.trace_func[position].func

    def _apply_trace_offset(self, addr):
        if self.project_baddr is None:
            return None
        offset = self.project_baddr - self.runtime_baddr
        return addr + offset

    def _statistics(self, trace_addrs):
        """
        :param trace: basic block address list
        """
        self.mapped_trace = [ ]
        for addr in trace_addrs:
            converted = self._apply_trace_offset(addr)
            if converted is not None:
                self.mapped_trace.append(converted)

        bbls = filter(self._get_bbl, self.mapped_trace)

        for p, bbl_addr in enumerate(bbls):
            block = self.workspace.instance.project.factory.block(bbl_addr)
            for addr in block.instruction_addrs:
                self._positions[addr].append(p)

            node = self.workspace.instance.cfg.get_any_node(bbl_addr)
            if node is None: #try again without asssuming node is start of a basic block
                node = self.workspace.instance.cfg.get_any_node(bbl_addr, anyaddr=True)

            func_name = hex(bbl_addr) #default to using bbl_addr as name if none is not found
            func = None
            if node is not None:
                func_addr = node.function_address
                functions = self.workspace.instance.project.kb.functions
                if func_addr in functions:
                    func_name = functions[func_addr].demangled_name
                    func = functions[func_addr]
                else:
                    func_name = "Unknown"
            else:
                l.warning("Node at %x is None, using bbl_addr as function name", bbl_addr)
            self.trace_func.append(TraceFunc(bbl_addr, func_name, func))

        self.count = len(self.trace_func)

    def _get_bbl(self, addr):
        try:
            return self.workspace.instance.project.factory.block(addr)
        except SimEngineError:
            return None

    def _func_addr(self, a):
        return self.workspace.instance.cfg.get_any_node(a).function_address

    def _func_name(self, a):
        return self.workspace.instance.project.kb.functions[self._func_addr(a)].demangled_name

    @staticmethod
    def _random_color():
        r = random.randint(0, 255)
        g = random.randint(0, 255)
        b = random.randint(0, 255)
        return QColor(r, g, b)

    def _get_position(self, addr, i):
        return self._positions[addr][i]
