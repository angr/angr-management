from typing import Optional
import logging

import darkdetect

from PySide6.QtCore import QTimer

from angrmanagement.config.color_schemes import COLOR_SCHEMES
from angrmanagement.ui.css import refresh_theme

from angrmanagement.config import Conf


_l = logging.getLogger(__name__)


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
    def create(cls, parent: Optional["QObject"]):
        """
        Create the singleton global theme object
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
        if enabled == self._enabled:
            return
        self._enabled = enabled
        if enabled:
            self._timer.timeout.connect(self._set_system)
        else:
            self._timer.timeout.disconnect(self._set_system)

    def enabled(self) -> bool:
        """
        Return True iff system theme tracking is enabled
        """
        return self._enabled

    def refresh_theme(self):
        """
        Force a refresh of the theme
        """
        if self._enabled:
            self._set_system(force=True)
        else:
            refresh_theme()

    #
    # Private methods
    #

    def __init__(self, parent, *, _caller=None):
        """
        This method is not public
        """
        if _caller != self.create:
            raise RuntimeError("Use .create(parent) or .get(); this is a singleton")
        # Init
        self._underlying: str = darkdetect.theme()
        self._enabled: bool = False
        self._timer = QTimer(parent)
        self._timer.start(50)

    def _set_system(self, *, force: bool = False):
        """
        Set the underlying theme according to the system theme if needed
        """
        new: str = darkdetect.theme()
        if force or new != self._underlying:
            self._underlying = new
            _l.debug("Underling color theme set to: ", new)
            Conf.theme_name = self._system if self._enabled else self._underlying
            for prop, value in COLOR_SCHEMES[new].items():
                setattr(Conf, prop, value)
            refresh_theme()
