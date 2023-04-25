# pylint:disable=missing-class-docstring
import logging
import os
import random
from bisect import bisect_left
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from angr.errors import SimEngineError
from PySide6.QtGui import QColor

log = logging.getLogger(name=__name__)


class TraceFunc:
    __slots__ = (
        "bbl_addr",
        "func_name",
        "func",
    )

    def __init__(self, bbl_addr=None, func_name=None, func=None):
        self.bbl_addr = bbl_addr
        self.func_name = func_name
        self.func = func


class ObjectAndBase:
    __slots__ = (
        "obj_name",
        "base_addr",
    )

    def __init__(self, obj_name: str, base_addr: int):
        self.obj_name = obj_name
        self.base_addr = base_addr

    def __lt__(self, other):
        if isinstance(other, ObjectAndBase):
            return self.base_addr < other.base_addr
        elif isinstance(other, int):
            return self.base_addr < other
        raise TypeError("Unsupported type %s" % type(other))


class TraceStatistics:
    BBL_FILL_COLOR = QColor(0, 0xF0, 0xF0, 0xF)
    BBL_BORDER_COLOR = QColor(0, 0xF0, 0xF0)
    BBL_EMPTY_COLOR = QColor("white")

    def __init__(self, workspace, trace, baddr):
        self.workspace = workspace
        self.trace: Dict[str, Any] = trace
        self.bbl_addrs = trace["bb_addrs"]
        self.syscalls = trace["syscalls"]
        self.id = trace["id"]
        self.created_at = trace["created_at"]
        self.input_id = trace["input_id"]
        self.complete = trace["complete"]
        self.mapping: Optional[List[ObjectAndBase]] = None
        if "map" in trace:
            map_dict: Dict[str, int] = trace["map"]
            self.mapping = [ObjectAndBase(name, base_addr) for name, base_addr in map_dict.items()]
            self.mapping = sorted(self.mapping, key=lambda o: o.base_addr)  # sort it based on base addresses
        self.trace_func: List[TraceFunc] = []
        self.func_addr_in_trace: Set[int] = set()
        self._func_color = {}
        self.count = None
        self._mark_color = {}
        self._positions = defaultdict(list)
        self.mapped_trace = []

        self.project = self.workspace.main_instance.project
        if self.project.am_none:
            self.project_baddr = None
        else:
            # only used if self.mapping is not available
            self.project_baddr = self.project.loader.main_object.mapped_base
        self.runtime_baddr = baddr  # this will not be used if self.mapping is available

        self._cached_object_project_base_addrs: Dict[str, int] = {}

        self._statistics(self.bbl_addrs)

    def find_object_base_in_project(self, object_name: str) -> Optional[int]:
        """
        Find the base address of an object in angr project. Returns None if the project is not mapped. Results are
        cached in self._cached_object_project_base_addrs.

        :param object_name: Name of the object to look for.
        :return:            The base address of the loaded object in angr Project.
        """

        try:
            return self._cached_object_project_base_addrs[object_name]
        except KeyError:
            pass

        base_addr = None
        base_obj_name = os.path.basename(object_name)
        for obj in self.project.loader.all_objects:
            if not hasattr(obj, "binary"):
                continue
            if obj.binary and os.path.basename(obj.binary) == base_obj_name:
                # found it!
                # we assume binary names are unique. if they are not, someone should the logic here.
                base_addr = obj.mapped_base
                break

        if base_addr is None:
            log.warning(
                "Cannot find object %s in angr project. Maybe it has not been loaded. Exclude it from the trace.",
                object_name,
            )
        self._cached_object_project_base_addrs[object_name] = base_addr
        return base_addr

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
            log.error(e)
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

    def _apply_trace_offset(self, addr) -> Optional[int]:
        if self.mapping is not None and self.mapping:
            # find the base address that this address belongs to
            idx = bisect_left(self.mapping, addr)
            obj = None
            if 0 <= idx < len(self.mapping):
                # check if addr == object.base
                obj = self.mapping[idx]
                if addr == obj.base_addr:
                    # yes
                    pass
                elif idx > 0:
                    obj = self.mapping[idx - 1]
            else:  # idx == len(self.mapping)
                obj = self.mapping[idx - 1]

            if obj is not None:
                project_base_addr = self.find_object_base_in_project(obj.obj_name)
                if project_base_addr is not None:
                    return addr + (project_base_addr - obj.base_addr)
                else:
                    # not found - the object is probably not loaded in angr? ignore it
                    return None

        # fall back
        if self.project_baddr is not None:
            offset = self.project_baddr - self.runtime_baddr
            return addr + offset
        else:
            # this object is probably created before an angr project is created. just give up.
            return None

    def _statistics(self, trace_addrs):
        """
        :param trace: basic block address list
        """
        self.mapped_trace = []
        for addr in trace_addrs:
            converted_addr = self._apply_trace_offset(addr)
            if converted_addr is not None:
                self.mapped_trace.append(converted_addr)

        bbls = filter(self._get_bbl, self.mapped_trace)
        functions = self.workspace.main_instance.project.kb.functions

        for p, bbl_addr in enumerate(bbls):
            node = self.workspace.main_instance.cfg.get_any_node(bbl_addr)
            # if node is None:  # try again without assuming node is start of a basic block
            #     node = self.workspace.instance.cfg.get_any_node(bbl_addr, anyaddr=True)

            func = None
            if node is not None:
                if node.instruction_addrs is not None:
                    instr_addrs = node.instruction_addrs
                else:
                    # relift
                    block = self.workspace.main_instance.project.factory.block(bbl_addr)
                    instr_addrs = block.instruction_addrs
                for addr in instr_addrs:
                    self._positions[addr].append(p)

                func_addr = node.function_address
                if func_addr is not None and functions.contains_addr(func_addr):
                    func = functions.get_by_addr(func_addr)
                    func_name = func.demangled_name
                else:
                    func_name = "Unknown"
                self.func_addr_in_trace.add(func_addr)
            else:
                # Node is not found in the CFG. It's possible that the library is not loaded
                func_name = hex(bbl_addr)  # default to using bbl_addr as name if none is not found
                # log.warning("Node at %x is None, using bbl_addr as function name", bbl_addr)
            self.trace_func.append(TraceFunc(bbl_addr, func_name, func))

            if p % 5000 == 0:
                print("... trace loading progress: %.02f%%" % (p * 100 / len(self.mapped_trace)))

        print("Trace is loaded.")
        self.count = len(self.trace_func)

    def _get_bbl(self, addr):
        try:
            return self.workspace.main_instance.project.factory.block(addr)
        except SimEngineError:
            return None

    def _func_addr(self, a):
        return self.workspace.main_instance.cfg.get_any_node(a).function_address

    def _func_name(self, a):
        return self.workspace.main_instance.project.kb.functions[self._func_addr(a)].demangled_name

    @staticmethod
    def _random_color():
        r = random.randint(0, 255)
        g = random.randint(0, 255)
        b = random.randint(0, 255)
        return QColor(r, g, b)

    def _get_position(self, addr, i):
        return self._positions[addr][i]
