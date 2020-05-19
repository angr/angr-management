
import time
import sys
import subprocess
import threading
import binascii

import rpyc
from rpyc.utils.server import ThreadedServer

from ..logic.singleton import SingleInstance, SingleInstanceException
from ..utils.env import app_path


DEFAULT_PORT = 64000

CONNECTIONS = { }
MD5toCONN = { }
SHA256toCONN = { }


class ManagementService(rpyc.Service):

    def _get_conn(self, md5, sha256):

        if md5 in MD5toCONN:
            conn = MD5toCONN[md5]
        elif sha256 in SHA256toCONN:
            conn = SHA256toCONN[sha256]
        else:
            raise Exception("The specified binary %s/%s is not open in angr management. We have the following ones: %s." % (
                md5,
                sha256,
                str(MD5toCONN)))
        return conn

    def on_connect(self, conn):
        self._conn = conn
        CONNECTIONS[conn] = None

    def on_disconnect(self, conn):
        self._conn = None
        if conn in CONNECTIONS:
            del CONNECTIONS[conn]

    def exposed_open(self, bin_path):
        flags = { }
        if sys.platform.startswith("win"):
            DETACHED_PROCESS = 0x00000008
            flags['creationflags'] = DETACHED_PROCESS

        apppath = app_path(pythonw=False, as_list=True)
        shell = True if sys.platform.startswith("win") else False
        # default to using daemon
        # if the user chooses to use angr URL scheme to load a binary, they are more likely to keep interacting with
        # this binary using angr URL scheme, which requires the angr management instance to run in with-daemon mode.
        proc = subprocess.Popen(apppath + ["-d", bin_path], shell=shell, stdin=None, stdout=None,
                                stderr=None,
                                close_fds=True, **flags)

    def exposed_jumpto(self, addr, symbol, md5, sha256):

        conn = self._get_conn(md5, sha256)
        conn.root.jumpto(addr, symbol)

    def exposed_register_binary(self, bin_path, md5, sha256):
        md5 = binascii.hexlify(md5).decode("ascii")
        sha256 = binascii.hexlify(sha256).decode("ascii")

        MD5toCONN[md5] = self._conn
        SHA256toCONN[sha256] = self._conn

    def exposed_commentat(self, addr, comment, md5, sha256):
        """

        :param addr:
        :param str comment:
        :param md5:
        :param sha256:
        :return:
        """

        conn = self._get_conn(md5, sha256)
        conn.root.commentat(addr, comment)

    def exposed_openbitmap(self, bitmap_path, base, md5, sha256):

        conn = self._get_conn(md5, sha256)
        conn.root.openbitmap(bitmap_path, base)

    def exposed_exit(self):
        pass

    def exposed_custom_binary_aware_action(self, md5, sha256, action, kwargs):
        conn = self._get_conn(md5, sha256)
        conn.root.custom_binary_aware_action(action, kwargs)


def monitor_thread(server):
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


def start_daemon(port=DEFAULT_PORT):

    try:
        from ..logic import GlobalInfo
        GlobalInfo.daemon_inst = SingleInstance()
    except SingleInstanceException:
        return

    # load plugins in headless mode
    from ..plugins import PluginManager
    GlobalInfo.headless_plugin_manager = PluginManager(None)
    GlobalInfo.headless_plugin_manager.discover_and_initialize_plugins()

    # start the server
    server = ThreadedServer(ManagementService, port=port, protocol_config={'allow_public_attrs': True})
    threading.Thread(target=monitor_thread, args=(server, ), daemon=True).start()
    server.start()


def daemon_exists():
    try:
        inst = SingleInstance()
    except SingleInstanceException:
        return True
    del inst
    return False


def run_daemon_process():
    """
    Start a new Python process to run daemon.

    :return:
    """

    flags = { }
    if sys.platform.startswith("win"):
        DETACHED_PROCESS = 0x00000008
        flags['creationflags'] = DETACHED_PROCESS

    apppath = app_path(pythonw=True, as_list=True)
    proc = subprocess.Popen(apppath + ["-D"], stdin=None, stdout=None, stderr=None,
                            close_fds=True, **flags)


def daemon_conn(port=DEFAULT_PORT, service=None):
    kwargs = { }
    if service is not None:
        kwargs['service'] = service
    kwargs['config'] = {'allow_public_attrs': True}
    conn = rpyc.connect("localhost", port, **kwargs)
    return conn
