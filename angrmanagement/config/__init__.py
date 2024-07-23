from __future__ import annotations

import os

from PySide6.QtCore import QStandardPaths

from .config_manager import ConfigurationManager

# Global configuration manager instance
config_dir: str = QStandardPaths.locate(
    QStandardPaths.StandardLocation.AppConfigLocation, "angr-management", QStandardPaths.LocateOption.LocateDirectory
)
if config_dir == "":
    system_config_dir = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppConfigLocation)
    if system_config_dir == "":
        print("Could not find configuration directory - settings will not be saved")
        config_dir = ""
    config_dir = os.path.join(system_config_dir, "angr-management")
    os.makedirs(config_dir, exist_ok=True)

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


APP_LOCATION = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
PLUGIN_PATH = str(os.path.join(APP_LOCATION, "plugins"))
RES_LOCATION = str(os.path.join(APP_LOCATION, "resources"))
IMG_LOCATION = str(os.path.join(RES_LOCATION, "images"))
FONT_LOCATION = str(os.path.join(RES_LOCATION, "fonts"))
THEME_LOCATION = str(os.path.join(RES_LOCATION, "themes"))
