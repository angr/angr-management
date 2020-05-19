
import logging
import functools

import rpyc

from ..logic.threads import gui_thread_schedule_async
from ..logic import GlobalInfo

_l = logging.getLogger(name=__name__)


def requires_daemon_conn(f):
    @functools.wraps(f)
    def with_daemon_conn(self, *args, **kwargs):
        if self.conn is None:
            return
        return f(self, *args, **kwargs)
    return with_daemon_conn


class ClientService(rpyc.Service):

    @property
    def instance(self):
        return GlobalInfo.main_window.workspace.instance

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

    def exposed_openbitmap(self, bitmap_path, base):

        if self.instance is not None:
            if hasattr(self.instance, "open_bitmap_multi_trace"):
                # try to parse base as a hex
                try:
                    base_addr = int(base, 16)
                except ValueError:
                    base_addr = None
                gui_thread_schedule_async(GlobalInfo.main_window.bring_to_front)
                gui_thread_schedule_async(self.instance.open_bitmap_multi_trace,
                                          args=(bitmap_path,),
                                          kwargs={
                                              'base_addr': base_addr,
                                          })
            else:
                _l.critical("TracePlugin is probably not installed.")
                # TODO: Open a message box

    def exposed_custom_binary_aware_action(self, action, kwargs):
        kwargs_copy = dict(kwargs.items())  # copy it to local
        DaemonClient.invoke(action, kwargs_copy)


class DaemonClientCls:
    """
    Implements logic that the client needs to talk to the daemon service.
    """

    def __init__(self, custom_handlers=None):
        self.custom_handlers = {}

    def register_handler(self, action:str, handler):
        self.custom_handlers[action] = handler

    def invoke(self, action, kwargs):
        if action not in self.custom_handlers:
            _l.critical("Unregistered URL action \"%s\"." % action)
            return
        self.custom_handlers[action](kwargs)

    @property
    def conn(self):
        return GlobalInfo.daemon_conn

    @requires_daemon_conn
    def register_binary(self, binary_name, md5, sha256):
        self.conn.root.register_binary(binary_name, md5, sha256)

    @requires_daemon_conn
    def exit(self):
        self.conn.exit()


DaemonClient = DaemonClientCls()
