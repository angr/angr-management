import logging
import random
from collections import defaultdict

from PySide2.QtGui import QColor
from angr.errors import SimEngineError

l = logging.getLogger(name=__name__)
l.setLevel('DEBUG')


class TraceFunc:
    def __init__(self, bbl_addr=None, func_name=None):
        self.bbl_addr = bbl_addr
        self.func_name = func_name


class TraceStatistics:

    BBL_FILL_COLOR = QColor(0, 0xf0, 0xf0, 0xf)
    BBL_BORDER_COLOR = QColor(0, 0xf0, 0xf0)

    def __init__(self, workspace, trace):
        self.workspace = workspace
        self.trace = trace
        self.trace_func = []
        self._func_color = {}
        self.count = None
        self._mark_color = {}
        self._positions = defaultdict(list)

        self._statistics(trace)

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
        return self._mark_color[self._get_position(addr, i)]

    def get_positions(self, addr):
        return self._positions[addr]

    def get_count(self, ins):
        return len(self._positions[ins])

    def get_bbl_from_position(self, position):
        return self.trace_func[position].bbl_addr

    def get_func_name_from_position(self, position):
        return self.trace_func[position].func_name

    def _statistics(self, trace):
        """
        :param trace: basic block address list
        """
        bbls = filter(self._get_bbl, trace)

        for p, bbl_addr in enumerate(bbls):
            block = self.workspace.instance.project.factory.block(bbl_addr)
            for addr in block.instruction_addrs:
                self._positions[addr].append(p)

            node = self.workspace.instance.cfg.get_any_node(bbl_addr)
            if(node == None):
                l.debug("Node at %x is None, skipping", bbl_addr)
                continue
            func_addr = node.function_address
            func_name = self.workspace.instance.project.kb.functions[func_addr].name
            self.trace_func.append(TraceFunc(bbl_addr, func_name))

        self.count = len(self.trace_func)

    def _get_bbl(self, addr):
        try:
            return self.workspace.instance.project.factory.block(addr)
        except SimEngineError:
            return None

    def _func_addr(self, a):
        return self.workspace.instance.cfg.get_any_node(a).function_address

    def _func_name(self, a):
        return self.workspace.instance.project.kb.functions[self._func_addr(a)].name

    def _random_color(self):
        r = random.randint(0, 255)
        g = random.randint(0, 255)
        b = random.randint(0, 255)
        return QColor(r, g, b)

    def _get_position(self, addr, i):
        return self._positions[addr][i]

