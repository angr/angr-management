import functools
import logging

import rpyc

from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.threads import gui_thread_schedule_async

_l = logging.getLogger(name=__name__)


def requires_daemon_conn(f):
    @functools.wraps(f)
    def with_daemon_conn(self, *args, **kwargs):
        if self.conn is None:
            return None
        return f(self, *args, **kwargs)

    return with_daemon_conn


class ClientService(rpyc.Service):
    @property
    def instance(self):
        return GlobalInfo.main_window.workspace.main_instance

    @property
    def workspace(self):
        return GlobalInfo.main_window.workspace

    def exposed_jumpto(self, addr, symbol):
        if self.workspace is not None:
            gui_thread_schedule_async(GlobalInfo.main_window.bring_to_front)
            if addr is not None:
                gui_thread_schedule_async(self.workspace.jump_to, args=(addr,))
            elif symbol is not None:
                # TODO: Support it
                gui_thread_schedule_async(self.workspace.jump_to, args=(symbol,))

    def exposed_commentat(self, addr, comment):
        if self.workspace is not None:
            if addr is not None:
                gui_thread_schedule_async(GlobalInfo.main_window.bring_to_front)
                gui_thread_schedule_async(self.workspace.set_comment(addr, comment))

    def exposed_custom_binary_aware_action(self, action, kwargs):  # pylint: disable=no-self-use
        kwargs_copy = dict(kwargs.items())  # copy it to local
        DaemonClient.invoke(action, kwargs_copy)


class DaemonClientCls:
    """
    Implements logic that the client needs to talk to the daemon service.
    """

    def __init__(self, custom_handlers=None):
        self.custom_handlers = {} if custom_handlers is None else custom_handlers

    def register_handler(self, action: str, handler):
        self.custom_handlers[action] = handler

    def invoke(self, action, kwargs):
        if action not in self.custom_handlers:
            _l.critical("Unregistered URL action %r", action)
            return
        self.custom_handlers[action](kwargs)

    @property
    def conn(self):
        return GlobalInfo.daemon_conn

    @requires_daemon_conn
    def register_binary(self, binary_name: str, target_id: str):
        self.conn.root.register_binary(binary_name, target_id)

    @requires_daemon_conn
    def exit(self):
        self.conn.exit()


DaemonClient = DaemonClientCls()
