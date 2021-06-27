from typing import List

from angr.knowledge_plugins.sync.sync_manager import SyncController
from angr.knowledge_plugins.functions import Function

try:
    import binsync
except ImportError:
    binsync = None


class Controller:
    def __init__(self, workspace):
        self.workspace = workspace
        self.sync_ctrl: SyncController = self.workspace.instance.sync

    def connect(self):
        self.sync_ctrl.connect()

    def fill_function(self, func: Function, user):
        # ==== Function Name ==== #
        _func: binsync.data.Function = self.sync_ctrl.pull_function(func.addr, user=user)
        if _func is None:
            # the function does not exist for that user's state
            return
        func.name = _func.name

        # ==== Comments ==== #
        cmts: List[binsync.data.Comment] = self.sync_ctrl.pull_comments(func.addr)
        for cmt in cmts:
            if cmt.comment:
                self.workspace.instance.kb.comments[cmt.addr] = cmt.comment

        # ==== Stack Vars ==== #
        self.workspace.instance.kb






    def users(self):
        return
