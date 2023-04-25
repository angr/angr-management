from typing import Optional, Callable
from threading import Lock
import logging

from PySide6.QtCore import QObject, QThread
import darkdetect

from angrmanagement.config.color_schemes import COLOR_SCHEMES
from angrmanagement.logic.threads import gui_thread_schedule_async
from angrmanagement.ui.css import refresh_theme
from angrmanagement.config import Conf


_l = logging.getLogger(__name__)


class _QListener(QObject):
    """
    A QObject wrapper around a darkdetect Listener
    """

    def __init__(self, callback: Callable[[str], None]):
        """
        :param callback: The callback to be invoked on theme change
        """
        self.listener = darkdetect.Listener(callback)
        super().__init__()

    def listen(self) -> None:
        """
        Start listening
        """
        self.listener.listen()


class TrackSystemTheme:
    """
    A singleton global theme class
    """

    _object: Optional["TrackSystemTheme"] = None
    _system: str = "System"

    #
    # Public methods
    #

    @classmethod
    def create(cls, parent: Optional[QObject]):
        """
        Create the singleton global theme object
        This function is not thread safe until after its first run
        """
        if cls._object is not None:
            raise RuntimeError(f"Refusing to create a second {cls.__name__}")
        cls._object = cls(parent, _caller=cls.create)
        return cls._object

    @classmethod
    def get(cls):
        """
        Get the singleton global theme object
        """
        if cls._object is None:
            raise RuntimeError(f"No existing {cls.__name__}")
        return cls._object

    def set_enabled(self, enabled: bool):
        """
        Connect system tracking slots as needed
        Note: This will not update the theme until the system state changes
        """
        with self._lock:
            if enabled == self.enabled():
                return
            self._enabled = enabled
            if enabled:
                self._thread = QThread(self._parent)  # Keep a reference to keep the thread alive
                self._listener = _QListener(self._set_theme)
                self._listener.moveToThread(self._thread)
                self._thread.started.connect(self._listener.listen)
                self._thread.start()
            else:
                self._listener.listener.stop(0.05)  # .05 to give a moment to clean up
                self._thread.terminate()
                self._listener = None
                self._thread = None  # Remove reference counted reference

    def enabled(self) -> bool:
        """
        Return True iff system theme tracking is enabled
        """
        return self._enabled

    def refresh_theme(self):
        """
        Force a refresh of the theme
        """
        if self.enabled():
            self._set_theme(darkdetect.theme(), force=True)
        else:
            gui_thread_schedule_async(refresh_theme)

    #
    # Private methods
    #

    def __init__(self, parent: Optional[QObject], *, _caller=None):
        """
        This method is not public
        """
        if _caller != self.create:  # pylint: disable=comparison-with-callable
            raise RuntimeError("Use .create(parent) or .get(); this is a singleton")
        # Init
        self._lock = Lock()
        self._parent = parent
        self._underlying: str = darkdetect.theme()
        self._enabled: bool = False
        self._listener: Optional[_QListener] = None
        self._thread: Optional[QThread] = None

    def _set_theme(self, theme: str, *, force: bool = False):
        """
        Set the underlying theme according to the system theme if needed
        """
        if force or theme != self._underlying:
            self._underlying = theme
            Conf.theme_name = self._underlying
            for prop, value in COLOR_SCHEMES[theme].items():
                setattr(Conf, prop, value)
            gui_thread_schedule_async(refresh_theme)
