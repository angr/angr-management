# pylint:disable=import-outside-toplevel,unused-argument
from __future__ import annotations

import subprocess
import sys
import threading
import time
from typing import TYPE_CHECKING

import rpyc
from rpyc.utils.server import ThreadedServer

from angrmanagement.logic.singleton import SingleInstance, SingleInstanceException
from angrmanagement.utils.env import app_path

if TYPE_CHECKING:
    from collections.abc import Callable

DEFAULT_PORT = 64000

CONNECTIONS = {}
TargetIDtoCONN = {}


class ManagementService(rpyc.Service):
    """
    Implements a binary management service. All daemon-enabled angr management will connect to this service and
    register the binary and target ID with this service.
    """

    _conn = None

    @staticmethod
    def _get_conn(target_id):
        if target_id in TargetIDtoCONN:
            conn = TargetIDtoCONN[target_id]
        else:
            raise Exception(
                f"The specified target {target_id} is not open in angr management. "
                f"We have the following ones: {str(TargetIDtoCONN)}."
            )
        return conn

    def on_connect(self, conn) -> None:
        self._conn = conn
        CONNECTIONS[conn] = None

    def on_disconnect(self, conn) -> None:
        self._conn = None
        if conn in CONNECTIONS:
            del CONNECTIONS[conn]

    def exposed_open(self, bin_path) -> None:
        if bin_path is None:
            return

        flags = {}
        if sys.platform.startswith("win"):
            DETACHED_PROCESS = 0x00000008
            flags["creationflags"] = DETACHED_PROCESS

        apppath = app_path(pythonw=False, as_list=True)
        shell = sys.platform.startswith("win")
        # default to using daemon
        # if the user chooses to use angr URL scheme to load a binary, they are more likely to keep interacting with
        # this binary using angr URL scheme, which requires the angr management instance to run in with-daemon mode.
        subprocess.Popen(
            apppath + ["-d", bin_path], shell=shell, stdin=None, stdout=None, stderr=None, close_fds=True, **flags
        )

    def exposed_jumpto(self, addr: int, symbol, target_id: str) -> None:
        conn = self._get_conn(target_id)
        conn.root.jumpto(addr, symbol)

    def exposed_register_binary(self, bin_path, target_id: str) -> None:
        TargetIDtoCONN[target_id] = self._conn

    def exposed_commentat(self, addr: int, comment: str, target_id: str) -> None:
        conn = self._get_conn(target_id)
        conn.root.commentat(addr, comment)

    def exposed_exit(self) -> None:
        pass

    def exposed_custom_binary_aware_action(self, target_id: str, action, kwargs) -> None:
        conn = self._get_conn(target_id)
        conn.root.custom_binary_aware_action(action, kwargs)


def monitor_thread(server) -> None:
    """
    Monitors connection status, and kills the server (which is, the daemon process) after the last active connection is
    gone for 5 minutes.
    """

    last_active_conn = time.time()

    while True:
        if CONNECTIONS:
            # print("[*] Has %d active connections." % len(CONNECTIONS))
            last_active_conn = time.time()
        else:
            # print("[*] No active connection for %d seconds." % (time.time() - last_active_conn))
            pass

        if time.time() - last_active_conn > 300:
            # kill myself
            # print("[-] Shutting down the server.")
            server.close()
            break

        if server._closed:
            break

        time.sleep(1)


def start_daemon(port: int = DEFAULT_PORT) -> None:
    try:
        from angrmanagement.logic import GlobalInfo

        GlobalInfo.daemon_inst = SingleInstance()
    except SingleInstanceException:
        return

    # load plugins in headless mode
    from angrmanagement.plugins import PluginManager

    GlobalInfo.headless_plugin_manager = PluginManager(None)
    GlobalInfo.headless_plugin_manager.discover_and_initialize_plugins()

    # start the server
    server = ThreadedServer(ManagementService, port=port, protocol_config={"allow_public_attrs": True})
    threading.Thread(target=monitor_thread, args=(server,), daemon=True).start()
    server.start()


def daemon_exists() -> bool:
    try:
        inst = SingleInstance()
    except SingleInstanceException:
        return True
    del inst
    return False


def run_daemon_process() -> None:
    """
    Start a new Python process to run daemon.

    :return:
    """

    flags = {}
    if sys.platform.startswith("win"):
        DETACHED_PROCESS = 0x00000008
        flags["creationflags"] = DETACHED_PROCESS

    apppath = app_path(pythonw=True, as_list=True)
    subprocess.Popen(apppath + ["-D"], stdin=None, stdout=None, stderr=None, close_fds=True, **flags)


def daemon_conn(port: int = DEFAULT_PORT, service=rpyc.VoidService):
    return rpyc.connect("localhost", port, service=service, config={"allow_public_attrs": True})


def register_server_exposed_method(method_name: str, method: Callable) -> None:
    setattr(ManagementService, f"exposed_{method_name}", method)
