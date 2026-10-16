from __future__ import annotations

import os
import sys

import platformdirs

from .config_manager import ConfigurationManager

APP_NAME = "angr-management"


def _legacy_config_dir() -> str | None:
    """
    The directory the Qt frontend used to keep its configuration in, QStandardPaths' AppConfigLocation for an
    application named angr-management.

    That is ``~/.config/angr-management`` on Linux (``$XDG_CONFIG_HOME`` if set),
    ``~/Library/Preferences/angr-management`` on macOS, and ``%LOCALAPPDATA%\\angr-management`` on Windows.
    """
    if sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library", "Preferences", APP_NAME)
    if sys.platform == "win32":
        local_appdata = os.environ.get("LOCALAPPDATA")
        return os.path.join(local_appdata, APP_NAME) if local_appdata else None
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(xdg_config_home, APP_NAME)


def _find_config_dir() -> str:
    """
    Pick the configuration directory, creating it if needed. "" means there is none and settings are not saved.

    The rule: ANGR_MANAGEMENT_CONFIG_DIR wins if it is set. Otherwise, if the directory that earlier versions of
    angr management used (QStandardPaths' AppConfigLocation) exists, keep using it. Otherwise use platformdirs'
    user configuration directory. The two are the same path on Linux and Windows; they differ on macOS, where Qt used
    ``~/Library/Preferences/angr-management`` and platformdirs uses ``~/Library/Application Support/angr-management``.
    """
    override = os.environ.get("ANGR_MANAGEMENT_CONFIG_DIR")
    if override:
        candidate = override
    else:
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
