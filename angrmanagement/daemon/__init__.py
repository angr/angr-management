
import os
import sys
import subprocess
import binascii

import tendo.singleton
import rpyc
from rpyc.utils.server import ThreadedServer
from rpyc.utils.helpers import BgServingThread


DEFAULT_PORT = 64000

CONNECTIONS = { }
MD5toCONN = { }
SHA256toCONN = { }


class ManagementService(rpyc.Service):

    def on_connect(self, conn):
        self._conn = conn
        CONNECTIONS[conn] = None

    def on_disconnect(self, conn):
        self._conn = None
        CONNECTIONS[conn] = None

    def exposed_open(self, bin_path):
        flags = { }
        if sys.platform.startswith("win"):
            DETACHED_PROCESS = 0x00000008
            flags['creationflags'] = DETACHED_PROCESS

        python_path = os.path.normpath(sys.executable)
        if sys.platform.startswith("win"):
            python_path = python_path.replace("pythonw.exe", "python.exe")
        proc = subprocess.Popen([python_path, "-m", "angrmanagement", bin_path], shell=True, stdin=None, stdout=None,
                                stderr=None,
                                close_fds=True, **flags)

    def exposed_jumpto(self, addr, symbol, md5, sha256):

        if md5 in MD5toCONN:
            conn = MD5toCONN[md5]
        elif sha256 in SHA256toCONN:
            conn = SHA256toCONN[sha256]
        else:
            raise Exception("The specified binary %s/%s is not open in angr management. We have the following ones: %s." % (
                md5,
                sha256,
                str(MD5toCONN)))

        conn.root.jumpto(addr, symbol)

    def exposed_register_binary(self, bin_path, md5, sha256):
        del CONNECTIONS[self._conn]

        md5 = binascii.hexlify(md5).decode("ascii")
        sha256 = binascii.hexlify(sha256).decode("ascii")

        MD5toCONN[md5] = self._conn
        SHA256toCONN[sha256] = self._conn

    def exposed_exit(self):
        pass


def start_daemon(port=DEFAULT_PORT):

    try:
        inst = tendo.singleton.SingleInstance()
    except tendo.singleton.SingleInstanceException:
        return

    server = ThreadedServer(ManagementService, port=port)
    server.start()


def daemon_exists():
    try:
        inst = tendo.singleton.SingleInstance()
    except tendo.singleton.SingleInstanceException:
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

    python_path = os.path.normpath(sys.executable)
    if sys.platform.startswith("win"):
        python_path = python_path.replace("python.exe", "pythonw.exe")
    proc = subprocess.Popen([python_path, "-m", "angrmanagement", "-d"], stdin=None, stdout=None, stderr=None,
                            close_fds=True, **flags)


def daemon_conn(port=DEFAULT_PORT, service=None, allow_callback=False):
    kwargs = { }
    if service is not None:
        kwargs['service'] = service
    conn = rpyc.connect("localhost", port, **kwargs)
    #if allow_callback:
    #    BgServingThread(conn)
    return conn


def monkeypatch_rpyc():
    from rpyc.core.async_ import AsyncResult, AsyncResultTimeout

    def patched_wait(self):
        while not self._is_ready and not self._ttl.expired():
            self._conn.serve(0.01)
        if not self._is_ready:
            raise AsyncResultTimeout("result expired")

    AsyncResult.wait = patched_wait


monkeypatch_rpyc()

from .url_handler import handle_url
