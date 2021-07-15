from typing import Optional
from collections import OrderedDict
import threading
import datetime
import time
import os

from PySide2.QtWidgets import QMessageBox

from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator
from angr.knowledge_plugins.sync.sync_controller import SyncController
from angr import knowledge_plugins
import angr
from ...ui.views import CodeView

try:
    import binsync
except ImportError:
    binsync = None


#
#   Constants
#

class SyncControlStatus:
    """
    A struct-like class to describe constant for syncing status

    """
    NO_PROJECT = 0
    NO_SYNC = 1
    NO_SYNCREPO = 2
    CONNECTED_NO_REMOTE = 3
    CONNECTED = 4


STATUS_TEXT = {
    SyncControlStatus.NO_PROJECT: "No angr project",
    SyncControlStatus.NO_SYNC: "The current angr (or project) does not support binsync.",
    SyncControlStatus.NO_SYNCREPO: "Not connected to a sync repo",
    SyncControlStatus.CONNECTED_NO_REMOTE: "Connected to a sync repo (no remote)",
    SyncControlStatus.CONNECTED: "Connected to a sync repo",
}


#
#   BinsyncController
#

class BinsyncController:
    """
    The class used for all pushing/pulling and merging based actions with BinSync data.
    This class is resposible for handling callbacks that are done by changes from the local user
    and responsible for running a thread to get new changes from other users.
    """

    def __init__(self, workspace):
        self.workspace = workspace
        self.instance = workspace.instance
        self.info_panel = None

        # command locks
        self.queue_lock = threading.Lock()
        self.cmd_queue = OrderedDict()

        self._last_reload = time.time()

        # start the pull routine
        # pylint:disable=consider-using-with
        self.pull_thread = threading.Thread(target=self.pull_routine)
        self.pull_thread.setDaemon(True)
        self.pull_thread.start()

    #
    #   Worker Thread and Queue
    #

    def make_controller_cmd(self, cmd_func, *args, **kwargs):
        with self.queue_lock:
            self.cmd_queue[time.time()] = (cmd_func, args, kwargs)

    def eval_cmd_queue(self):
        cmd = None
        with self.queue_lock:
            if len(self.cmd_queue) > 0:
                # pop the first command from the queue
                cmd = self.cmd_queue.popitem(last=False)[1]

        # parse the command if present
        if cmd:
            func = cmd[0]
            f_args = cmd[1]
            f_kargs = cmd[2]

            # call it!
            func(*f_args, **f_kargs)

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

            if self.check_client():
                # run an operation every second
                self.eval_cmd_queue()

                # reload info panel every 10 seconds
                if self.info_panel is not None and time.time() - self._last_reload > 10:
                    try:
                        self._last_reload = time.time()
                        self.info_panel.reload()
                    except RuntimeError:
                        # the panel has been closed
                        self.info_panel = None

            # Snooze
            time.sleep(1)

    #
    #   State & Status Functions
    #

    @property
    def sync(self) -> SyncController:
        return self.instance.kb.sync

    def connect(self, user, path, bin_hash, init_repo=False, remote_url=None):
        self.sync.connect(user, path, bin_hash=bin_hash, init_repo=init_repo, remote_url=remote_url)
        warnings = self.sync.client.connection_warnings
        BinsyncController._parse_and_display_connection_warnings(warnings)

    def check_client(self, message_box=False):
        if self.instance.kb is None or not hasattr(self.instance.kb, 'sync') or self.instance.kb.sync.client is None:
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
        if not self.instance.project.kb.sync.has_remote:
            return SyncControlStatus.CONNECTED_NO_REMOTE
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
        decompilation = self.decompile_function(func)

        _func: binsync.data.Function = self.sync.pull_function(func.addr, user=user)
        if _func is None:
            # the function does not exist for that user's state
            return

        # ==== Function Name ==== #
        func.name = _func.name
        decompilation.cfunc.name = _func.name
        decompilation.cfunc.demangled_name = _func.name

        # ==== Comments ==== #
        sync_cmts = self.sync.pull_comments(func.addr, user=user)
        for addr, cmt in sync_cmts:
            if cmt.comment:
                if cmt.decompiled:
                    pos = decompilation.map_addr_to_pos.get_nearest_pos(addr)
                    corrected_addr = decompilation.map_pos_to_addr.get_node(pos).tags['ins_addr']
                    decompilation.stmt_comments[corrected_addr] = cmt.comment
                else:
                    self.instance.kb.comments[cmt.addr] = cmt.comment

        # ==== Stack Vars ==== #
        sync_vars = self.sync.pull_stack_variables(func.addr, user=user)
        for offset, sync_var in sync_vars:
            code_var = BinsyncController.find_stack_var_in_codegen(decompilation, offset)
            if code_var:
                code_var.name = sync_var.name
                code_var.renamed = True

        decompilation.regenerate_text()
        self.decompile_function(func, refresh_gui=True)

    #
    #   Pusher Alias
    #

    def push_stack_variable(self, func_addr, offset, name, type_, size_):
        return self.instance.kb.sync.push_stack_variable(func_addr, offset, name, type_, size_)

    def push_comment(self, addr, cmt, decompiled):
        return self.instance.kb.sync.push_comment(addr, cmt, decompiled=decompiled)

    def push_func(self, func: knowledge_plugins.functions.Function):
        return self.instance.kb.sync.push_function(func)

    #
    #   Utils
    #

    @staticmethod
    def _parse_and_display_connection_warnings(warnings):
        warning_text = ""

        for warning in warnings:
            if warning == binsync.ConnectionWarnings.HASH_MISMATCH:
                warning_text += "Warning: the hash stored for this BinSync project does not match"
                warning_text += " the hash of the binary you are attempting to analyze. It's possible"
                warning_text += " you are working on a different binary.\n"

        if len(warning_text) > 0:
            QMessageBox.warning(
                None,
                "BinSync: Connection Warnings",
                warning_text
            )

    def decompile_function(self, func, refresh_gui=False):
        # check for known decompilation
        available = self.instance.kb.structured_code.available_flavors(func.addr)
        should_decompile = False
        if 'pseudocode' not in available:
            should_decompile = True
        else:
            cached = self.instance.kb.structured_code[(func.addr, 'pseudocode')]
            if isinstance(cached, DummyStructuredCodeGenerator):
                should_decompile = True

        if should_decompile:
            # recover direct pseudocode
            self.instance.project.analyses.Decompiler(func, flavor='pseudocode')

            # attempt to get source code if its available
            source_root = None
            if self.instance.original_binary_path:
                source_root = os.path.dirname(self.instance.original_binary_path)
            self.instance.project.analyses.ImportSourceCode(func, flavor='source', source_root=source_root)

        # grab newly cached pseudocode
        decomp = self.instance.kb.structured_code[(func.addr, 'pseudocode')]
        if refresh_gui:
            # refresh all views
            self.workspace.reload()

            # re-decompile current view to cause a refresh
            current_tab = self.workspace.view_manager.current_tab
            if isinstance(current_tab, CodeView) and current_tab.function == func:
                self.workspace.decompile_current_function()

        return decomp

    @staticmethod
    def find_stack_var_in_codegen(decompilation, stack_offset: int) -> Optional[angr.sim_variable.SimStackVariable]:
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
        elif diff_sec >= 60 * 60:
            s = "%d hours" % int(diff_sec / 60 / 60)
        elif diff_sec >= 60:
            s = "%d minutes" % int(diff_sec / 60)
        else:
            s = "%d seconds" % diff_sec

        s += " ago" if ago else " in the future"
        return s
