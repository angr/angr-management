from typing import TYPE_CHECKING, List

from angr import options
from angr.state_plugins.heap import SimHeapPTMalloc
from sortedcontainers.sorteddict import SortedDict

from angrmanagement.plugins.base_plugin import BasePlugin

if TYPE_CHECKING:
    from angr.sim_state import SimState
    from angr.state_plugins.sim_action import SimAction


class MemoryChecker(BasePlugin):
    AllowList = ["free", "malloc", "__libc_start_main"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.states = self.workspace.main_instance.states
        self.states.am_subscribe(self.install_state_plugin)

    def install_state_plugin(self, **kwargs):
        if kwargs.get("src", None) != "new":
            return
        state: SimState = kwargs.get("state")
        state.register_plugin("heap", SimHeapPTMalloc())
        state.options.update({options.TRACK_MEMORY_ACTIONS})

    @staticmethod
    def eval_ptr(state, ptr):
        return state.solver.eval(ptr)

    @staticmethod
    def check_address_is_free(state: "SimState", ptr_list: "List[SimAction]"):
        ptr_dict = SortedDict([(MemoryChecker.eval_ptr(state, x.addr.ast), x) for x in ptr_list])
        len_list = len(ptr_dict)
        for chunk in state.heap.free_chunks():
            base = chunk.base
            size = state.solver.eval(chunk.get_size())
            p = ptr_dict.bisect_left(base)
            if p < len_list and base <= ptr_dict.peekitem(p)[0] < base + size:
                if state.posix.stderr.writable:
                    addr, act = ptr_dict.peekitem(p)
                    err_str = (
                        f"\n=== Use-After-Free Plugin ===\n"
                        f"Memory Address:{addr:#x}\n"
                        f"Instrument Address:{act.ins_addr:#x}\n"
                    )
                    state.posix.stderr.write(None, err_str.encode())
                return True
        return False

    @staticmethod
    def check_use_after_free(state: "SimState"):
        # heap: SimHeapPTMalloc = state.heap
        # heap.print_heap_state()

        actions: List[SimAction] = state.history.actions.hardcopy
        last_bbl_addr = actions[-1].bbl_addr
        address_list = []
        for act in reversed(actions):
            if act.bbl_addr != last_bbl_addr:
                break
            if act.type == "mem" and (
                act.sim_procedure is None or act.sim_procedure.display_name not in MemoryChecker.AllowList
            ):
                address_list.append(act)
        return MemoryChecker.check_address_is_free(state, address_list)

    def step_callback(self, simgr):
        simgr.move("active", "use_after_free", self.check_use_after_free)
