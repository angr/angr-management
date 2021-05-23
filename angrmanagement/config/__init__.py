
import os
import atexit

from xdg import BaseDirectory

from .config_manager import ConfigurationManager

# Global configuration manager instance
fc = BaseDirectory.save_config_path('angr-management')
if fc is not None:
    config_path = os.path.join(fc, 'config')
    try:
        with open(config_path, 'r') as f:
            Conf = ConfigurationManager.parse(f)
    except FileNotFoundError:
        Conf = ConfigurationManager()
else:
    print("Could not find configuration directory - settings will not be saved")
    Conf = ConfigurationManager()

def save_config():
    if fc is None:
        return
    with open(config_path, 'w') as f:
        Conf.save(f)
atexit.register(save_config)

APP_LOCATION = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
PLUGIN_PATH = str(os.path.join(APP_LOCATION, 'plugins'))
RES_LOCATION = str(os.path.join(APP_LOCATION, 'resources'))
IMG_LOCATION = str(os.path.join(RES_LOCATION, 'images'))
FONT_LOCATION = str(os.path.join(RES_LOCATION, 'fonts'))
