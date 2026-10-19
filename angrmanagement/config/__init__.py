from __future__ import annotations

import os
import sys

import platformdirs

from .config_manager import ConfigurationManager

APP_NAME = "angr-management"


#: the Qt application name angrmanagement.boot() used, so Qt kept that entry point's settings under this name
BOOT_APP_NAME = "angr"


def _legacy_config_dir(app_name: str = APP_NAME) -> str | None:
    """
    The directory the Qt frontend used to keep its configuration in, QStandardPaths' AppConfigLocation for an
    application named ``app_name``.

    For angr-management that is ``~/.config/angr-management`` on Linux (``$XDG_CONFIG_HOME`` if set),
    ``~/Library/Preferences/angr-management`` on macOS, and ``%LOCALAPPDATA%\\angr-management`` on Windows.
    """
    if sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library", "Preferences", app_name)
    if sys.platform == "win32":
        local_appdata = os.environ.get("LOCALAPPDATA")
        return os.path.join(local_appdata, app_name) if local_appdata else None
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(xdg_config_home, app_name)


def _running_qt_application_name() -> str | None:
    """The name of the running Qt application, or None if there is none. This never imports Qt."""
    qtcore = sys.modules.get("PySide6.QtCore")
    if qtcore is None:
        return None
    app = qtcore.QCoreApplication.instance()
    return None if app is None else app.applicationName()


def _find_config_dir() -> str:
    """
    Pick the configuration directory, creating it if needed. "" means there is none and settings are not saved.

    The rule: ANGR_MANAGEMENT_CONFIG_DIR wins if it is set. Otherwise, when the running Qt application is the one
    angrmanagement.boot() creates, named "angr", and the directory Qt kept its settings in under that name holds a
    config.toml, use that directory, as earlier versions did for boot(). Otherwise, if the directory that earlier
    versions of angr management used (QStandardPaths' AppConfigLocation) exists, keep using it. Otherwise use
    platformdirs' user configuration directory. That and the angr-management directory are the same path on Linux and
    Windows; they differ on macOS, where Qt used ``~/Library/Preferences/angr-management`` and platformdirs uses
    ``~/Library/Application Support/angr-management``.

    The "angr" directory needs a config.toml, not just to exist, because the name is not angr management's alone.
    """
    override = os.environ.get("ANGR_MANAGEMENT_CONFIG_DIR")
    if override:
        candidate = override
    else:
        if _running_qt_application_name() == BOOT_APP_NAME:
            boot_dir = _legacy_config_dir(BOOT_APP_NAME)
            if boot_dir is not None and os.path.isfile(os.path.join(boot_dir, "config.toml")):
                return boot_dir
        legacy = _legacy_config_dir()
        if legacy is not None and os.path.isdir(legacy):
            return legacy
        candidate = platformdirs.user_config_dir(APP_NAME, appauthor=False)
    try:
        os.makedirs(candidate, exist_ok=True)
    except OSError:
        return ""
    return candidate


# Global configuration manager instance
config_dir: str = _find_config_dir()

config_path: str | None
if config_dir != "":
    config_path = os.path.join(config_dir, "config.toml")
    try:
        Conf = ConfigurationManager.parse_file(config_path)
    except FileNotFoundError:
        Conf = ConfigurationManager()
else:
    config_path = None
    print("Could not find configuration directory - settings will not be saved")
    Conf = ConfigurationManager()


def save_config() -> None:
    if config_path is None:
        return
    Conf.save_file(config_path)
