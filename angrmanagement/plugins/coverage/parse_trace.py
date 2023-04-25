import bisect
import functools
import logging
import os
from typing import Dict, List, Optional, Tuple

from angr.errors import SimEngineError

log = logging.getLogger(__name__)


class ObjectAndBase:
    """
    Groups an object and its base address.
    """

    __slots__ = (
        "obj_name",
        "base_addr",
        "proj_base_addr",
    )

    def __init__(self, obj_name: str, base_addr: int, proj_base_addr: Optional[int]):
        self.obj_name = obj_name
        self.base_addr = base_addr
        self.proj_base_addr = proj_base_addr

    def __lt__(self, other):
        if isinstance(other, ObjectAndBase):
            return self.base_addr < other.base_addr
        elif isinstance(other, int):
            return self.base_addr < other
        raise TypeError("Unsupported type %s" % type(other))


def _valid_addr(addr, project):
    if not addr and addr != 0:
        return None
    try:
        return project.loader.find_object_containing(addr)
    except SimEngineError:
        return None


@functools.lru_cache(1024)
def _find_object_base_in_project(object_name, project):
    base_addr = None
    base_obj_name = os.path.basename(object_name)
    for obj in project.loader.all_objects:
        if not hasattr(obj, "binary"):
            continue
        if obj.binary and os.path.basename(obj.binary) == base_obj_name:
            # found it!
            # we assume binary names are unique. if they are not, then add the logic here.
            base_addr = obj.mapped_base
            break
    if base_addr is None:
        log.warning(
            "Cannot find object %s in angr project. Maybe it has not been loaded. Exclude it from the trace.",
            object_name,
        )
    return base_addr


# cache the last index
last_obj_idx: Optional[int] = None


def _find_obj_in_mapping(addr, mapping) -> Tuple[int, Optional[ObjectAndBase]]:
    idx = bisect.bisect_left(mapping, addr)
    obj = None
    if 0 <= idx < len(mapping):
        # check if addr == object.base
        obj = mapping[idx]
        if addr == obj.base_addr:
            # found
            pass
        elif idx > 0:
            idx = idx - 1
            obj = mapping[idx]
        else:  # idx == len(mapping)
            idx = idx - 1
            obj = mapping[idx]
    return idx, obj


def _apply_trace_offset(addr, mapping, project_baddr, runtime_baddr):
    global last_obj_idx

    if mapping is not None and mapping:
        # find the base address that this address belongs to
        if last_obj_idx is None or last_obj_idx >= len(mapping):
            idx, obj = _find_obj_in_mapping(addr, mapping)
            last_obj_idx = idx
        elif addr < mapping[last_obj_idx].base_addr:
            # find again
            idx, obj = _find_obj_in_mapping(addr, mapping)
            last_obj_idx = idx
        elif addr >= mapping[last_obj_idx + 1].base_addr:
            # find again
            idx, obj = _find_obj_in_mapping(addr, mapping)
            last_obj_idx = idx
        else:
            obj = mapping[last_obj_idx]

        if obj is not None:
            project_base_addr = obj.proj_base_addr
            if project_base_addr is not None:
                return addr + (project_base_addr - obj.base_addr)
            else:
                # not found - the object is probably not loaded in angr? ignore it
                return None

    # fall back
    if project_baddr is not None:
        offset = project_baddr - runtime_baddr
        return addr + offset
    else:
        # this object is probably created before an angr project is created. just give up.
        return None


def trace_to_bb_addrs(trace, project, trace_base):
    """
    convert the trace object to a list of basic blocks, using the given angr project
    """
    bbl_addrs = trace["bb_addrs"]

    mapping: Optional[List[ObjectAndBase]] = None
    if "map" in trace:
        map_dict: Dict[str, int] = trace["map"]
        mapping = [
            ObjectAndBase(name, base_addr, _find_object_base_in_project(name, project.am_obj))
            for name, base_addr in map_dict.items()
        ]
        mapping = sorted(mapping, key=lambda o: o.base_addr)  # sort it based on base addresses

    # only used if self.mapping is not available
    project_baddr = None if project.am_none else project.loader.main_object.mapped_base
    runtime_baddr = trace_base  # this will not be used if self.mapping is available

    # convert over all the trace adders using info from the trace
    to_return = filter(
        lambda a: _valid_addr(a, project),
        [_apply_trace_offset(addr, mapping, project_baddr, runtime_baddr) for addr in bbl_addrs],
    )
    return list(to_return)
