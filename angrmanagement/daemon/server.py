
import os
import sys
import subprocess
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
        CONNECTIONS[conn] = None

    def exposed_open(self, bin_path):
        flags = { }
        if sys.platform.startswith("win"):
            DETACHED_PROCESS = 0x00000008
            flags['creationflags'] = DETACHED_PROCESS

        apppath = app_path(pythonw=False, as_list=True)
        shell = True if sys.platform.startswith("win") else False
        proc = subprocess.Popen(apppath + [bin_path], shell=shell, stdin=None, stdout=None,
                                stderr=None,
                                close_fds=True, **flags)

    def exposed_jumpto(self, addr, symbol, md5, sha256):

        conn = self._get_conn(md5, sha256)
        conn.root.jumpto(addr, symbol)

    def exposed_register_binary(self, bin_path, md5, sha256):
        del CONNECTIONS[self._conn]

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


def start_daemon(port=DEFAULT_PORT):

    try:
        from ..logic import GlobalInfo
        GlobalInfo.daemon_inst = SingleInstance()
    except SingleInstanceException:
        return

    server = ThreadedServer(ManagementService, port=port)
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
    conn = rpyc.connect("localhost", port, **kwargs)
    return conn
