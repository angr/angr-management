from typing import List
from collections import OrderedDict
import threading
import datetime
import time

from PySide2.QtWidgets import QMessageBox

import angr
from angr.knowledge_plugins.sync.sync_manager import SyncController
from angr import knowledge_plugins

try:
    import binsync
    from binsync import data
except ImportError:
    binsync = None


#
#   Constants
#

class SyncControlStatus:
    NO_PROJECT = 0
    NO_SYNC = 1
    NO_SYNCREPO = 2
    CONNECTED = 3


STATUS_TEXT = {
    SyncControlStatus.NO_PROJECT: "No angr project",
    SyncControlStatus.NO_SYNC: "The current angr (or project) does not support binsync.",
    SyncControlStatus.NO_SYNCREPO: "Not connected to a sync repo",
    SyncControlStatus.CONNECTED: "Connected to a sync repo",
}


#
#   BinsyncController
#

class BinsyncController:
    def __init__(self, workspace):
        self.workspace = workspace
        self.instance = workspace.instance
        self.info_panel = None

        # command locks
        self.queue_lock = threading.Lock()
        self.cmd_queue = OrderedDict()

        # start the pull routine
        self.pull_thread = threading.Thread(target=self.pull_routine)
        self.pull_thread.setDaemon(True)
        self.pull_thread.start()

    #
    #   Worker Thread and Queue
    #

    def make_controller_cmd(self, cmd_func, *args, **kwargs):
        self.queue_lock.acquire()
        self.cmd_queue[time.time()] = (cmd_func, args, kwargs)
        self.queue_lock.release()

    def eval_cmd_queue(self):
        self.queue_lock.acquire()
        if len(self.cmd_queue) > 0:
            # pop the first command from the queue
            cmd = self.cmd_queue.popitem(last=False)[1]
            self.queue_lock.release()

            # parse the command
            func = cmd[0]
            f_args = cmd[1]
            f_kargs = cmd[2]

            # call it!
            func(*f_args, **f_kargs)
            return 0
        self.queue_lock.release()

    def pull_routine(self):
        while True:
            # pull the repo every 10 seconds
            if self.check_client() and self.instance.kb.sync.has_remote \
                    and (
                    self.instance.kb.sync.client._last_pull_attempt_at is None
                    or (datetime.datetime.now() - self.instance.kb.sync.client._last_pull_attempt_at).seconds > 10
            ):
                # Pull new items
                self.instance.kb.sync.pull()

                # reload the info panel if it's registered
                if self.info_panel is not None:
                    try:
                        self.info_panel.reload()
                    except RuntimeError:
                        # the panel has been closed
                        self.info_panel = None

            # run an operation every second
            if self.check_client() and self.instance.kb.sync.has_remote:
                self.eval_cmd_queue()

            # Snooze
            time.sleep(1)

    #
    #   State & Status Functions
    #

    def connect(self):
        self.instance.kb.sync.connect()

    @property
    def sync(self) -> SyncController:
        return self.instance.kb.sync

    def check_client(self, message_box=False):
        if self.instance.kb is None or self.instance.kb.sync is None or self.instance.kb.sync.client is None:
            if message_box:
                QMessageBox.critical(
                    None,
                    "BinSync: Error",
                    "BinSync client does not exist.\n"
                    "You haven't connected to a binsync repo. Please connect to a binsync repo first.",
                    QMessageBox.Ok,
                )
            return False
        return True

    @property
    def status(self):
        if self.instance.project is None:
            return SyncControlStatus.NO_PROJECT
        if not hasattr(self.instance.project.kb, 'sync'):
            return SyncControlStatus.NO_SYNC
        if not self.instance.project.kb.sync.connected:
            return SyncControlStatus.NO_SYNCREPO
        return SyncControlStatus.CONNECTED

    @property
    def status_string(self):
        s = self.status
        return STATUS_TEXT.get(s, "Unknown status.")

    #
    #   Display Fillers
    #

    def fill_function(self, func: knowledge_plugins.functions.Function, user):
        # re-decompile a function if needed
        self.workspace.decompile_function(func, headless=True)
        decompilation = self.instance.kb.structured_code[(func.addr, 'pseudocode')]

        _func: binsync.data.Function = self.sync.pull_function(func.addr, user=user)
        if _func is None:
            # the function does not exist for that user's state
            return

        # ==== Function Name ==== #
        func.name = _func.name
        decompilation.cfunc.name = _func.name
        decompilation.cfunc.demangled_name = _func.name

        # ==== Comments ==== #
        all_cmts: List[binsync.data.Comment] = self.sync.pull_comments(func.addr, user=user)
        for cmt in all_cmts:
            if cmt.comment:
                if cmt.decompiled:
                    pos = decompilation.map_addr_to_pos.get_nearest_pos(cmt.addr)
                    corrected_addr = decompilation.map_pos_to_addr.get_node(pos).tags['ins_addr']
                    decompilation.stmt_comments[corrected_addr] = cmt.comment

                else:
                    self.instance.kb.comments[cmt.addr] = cmt.comment

        # ==== Stack Vars ==== #
        sync_vars= self.sync.pull_stack_variables(func.addr, user=user)
        for offset, sync_var in sync_vars:
            code_var = self._find_stack_var_in_codegen(decompilation, offset)
            if code_var:
                code_var.name = sync_var.name
                code_var.renamed = True

        decompilation.regenerate_text()
        self.instance.workspace.decompile_function(func, headless=True)





    #
    #   Pusher Alias
    #

    def push_stack_variable(self, func_addr, offset, name, type_, size_):
        return self.instance.kb.sync.push_stack_variable(func_addr, offset, name, type_, size_)

    def push_comment(self, func_addr, addr, cmt, decompiled):
        import ipdb; ipdb.set_trace()
        return self.instance.kb.sync.push_comment(func_addr, addr, cmt, decompiled=decompiled)

    def push_func(self, func: knowledge_plugins.functions.Function):
        return self.instance.kb.sync.push_function(func)

    #
    #   Utils
    #

    def _find_stack_var_in_codegen(self, decompilation, stack_offset: int) -> angr.sim_variable.SimStackVariable:
        for var in decompilation.cfunc.variable_manager._unified_variables:
            if hasattr(var, "offset") and var.offset == stack_offset:
                return var

        return None

    def get_local_func_name(self, addr):
        """
        Returns the name of the function in your local decompilation given any addr. Will return an
        empty string if no function is found.

        @param addr:
        @return:
        """
        sync_ctrl = self.instance.kb.sync
        func_addr = sync_ctrl.get_func_addr_from_addr(addr)

        if func_addr:
            return self.workspace.instance.kb.functions[func_addr].name
        else:
            return ""

    @staticmethod
    def friendly_datetime(time_before):
        # convert
        if isinstance(time_before, int):
            dt = datetime.datetime.fromtimestamp(time_before)
        elif isinstance(time_before, datetime.datetime):
            dt = time_before
        else:
            return ""

        now = datetime.datetime.now()
        if dt <= now:
            diff = now - dt
            ago = True
        else:
            diff = dt - now
            ago = False
        diff_days = diff.days
        diff_sec = diff.seconds

        if diff_days >= 1:
            s = "%d days" % diff_days
            ago = diff_days < 0
        elif diff_sec >= 60 * 60:
            s = "%d hours" % int(diff_sec / 60 / 60)
        elif diff_sec >= 60:
            s = "%d minutes" % int(diff_sec / 60)
        else:
            s = "%d seconds" % diff_sec

        s += " ago" if ago else " in the future"
        return s

