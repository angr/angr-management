
import time
import threading

from .object_container import ObjectContainer


try:
    import binsync
except ImportError:
    binsync = None


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


class SyncControl:
    """
    Interfaces with project.kb.sync (so, please avoid duplicated logic). Provide properties with subscribable events.
    Routinely pulls updates and pushes new changes at a user-controllable interval.
    """
    def __init__(self, instance):
        self.instance = instance

        self.project = None
        self.users_container = ObjectContainer([], notes="All users in the current team.")

        # Subscribe to project creation
        self.instance.project_container.am_subscribe(self._initialize)

        # How often do we call the client and update our information?
        self._update_interval = 10

    @property
    def status(self):
        if self.project is None:
            return SyncControlStatus.NO_PROJECT
        if not hasattr(self.project.kb, 'sync'):
            return SyncControlStatus.NO_SYNC
        if not self.project.kb.sync.connected:
            return SyncControlStatus.NO_SYNCREPO
        return SyncControlStatus.CONNECTED

    @property
    def status_string(self):
        s = self.status
        return STATUS_TEXT.get(s, "Unknown status.")

    @property
    def users(self):
        return self.users_container.am_obj

    def _initialize(self):
        self.project = self.instance.project

    def connect(self, user, repo_path):

        if binsync is None:
            raise ImportError("binsync is not installed.")

        client = binsync.Client(user, repo_path)
        self.project.kb.sync.connect(client)

        # Spawn the worker thread
        thr = threading.Thread(target=self.worker_routine, daemon=True)
        thr.start()

    def worker_routine(self):
        while self.status == SyncControlStatus.CONNECTED:

            # update users
            self.users_container.am_obj = list(self.project.kb.sync.users())
            self.users_container.am_event()

            time.sleep(self._update_interval)
