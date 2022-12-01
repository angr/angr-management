from typing import Optional
import logging

import darkdetect

from PySide6.QtGui import QColor
from PySide6.QtCore import QTimer

from angrmanagement.config.color_schemes import COLOR_SCHEMES
from angrmanagement.config.config_manager import ENTRIES
from angrmanagement.ui.widgets.qcolor_option import QColorOption
from angrmanagement.ui.css import refresh_theme

from angrmanagement.config import Conf


_l = logging.getLogger(__name__)


class Theme:
    """
    A singleton global theme class
    """
    _object: Optional["Theme"] = None
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

    @property
    def themes(self):
        """
        The supported themes
        """
        return [self._system] + list(sorted(COLOR_SCHEMES))

    def current(self) -> Optional[str]:
        """
        Get the current theme
        """
        return self._system if self._tracking else self._underlying

    def set(self, name):
        """
        Set the theme
        """
        _l.debug("Setting theme to: ", name)
        if name == self._system:
            self._set_system()
            self._system_tracking(True)
        else:
            self._system_tracking(False)
            self._set_underlying(name)
            self._underlying = name

    def update_config_cache(self):
        """
        Edit the cached config to reflect the theme changes; does not save the config!
        """

    #
    # Private methods
    #

    def __init__(self, parent, *, _caller=None):
        """
        This method is not public
        """
        if _caller != self.create:
            raise RuntimeError("Use .create(parent) or .get(); this is a singleton")
        # For config file
        self._to_save = {}
        for ce in ENTRIES:
            if ce.type_ is not QColor:
                continue
            row = QColorOption(getattr(Conf, ce.name), ce.name)
            self._to_save[ce.name] = (ce, row)
        # Init
        self._underlying: Optional[str] = None
        self._tracking: bool = False
        self._timer = QTimer(parent)
        self._timer.start(50)
        # Load default theme
        self.set(Conf.theme_name)

    def _set_underlying(self, name):
        """
        Set the underling theme to 'name'
        """
        _l.debug("Underling color theme set to: ", name)
        self._underlying = name
        for prop, value in COLOR_SCHEMES[name].items():
            row = self._to_save[prop][1]
            row.set_color(value)
        Conf.theme_name = self.current()
        for ce, row in self._to_save.values():
            setattr(Conf, ce.name, row.color.am_obj)
        refresh_theme()

    def _set_system(self):
        """
        Set the underlying theme according to the system theme if needed
        """
        new: str = darkdetect.theme()
        if new != self._underlying:
            self._set_underlying(new)

    def _system_tracking(self, enabled: bool):
        """
        Connect system tracking slots as needed
        """
        if enabled == self._tracking:
            return
        self._tracking = enabled
        if enabled:
            self._timer.timeout.connect(self._set_system)
        else:
            self._timer.timeout.disconnect(self._set_system)
