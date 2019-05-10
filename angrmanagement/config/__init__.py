
import os

from xdg import BaseDirectory

from .config_manager import ConfigurationManager

# Global configuration manager instance
fc = BaseDirectory.load_first_config('angr-management')
if fc is not None:
    config_path = os.path.join(fc, 'config')
    with open(config_path, 'r') as f:
        Conf = ConfigurationManager.parse(f)
else:
    Conf = ConfigurationManager()

APP_LOCATION = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
PLUGIN_PATH = str(os.path.join(APP_LOCATION, 'plugins'))
RES_LOCATION = str(os.path.join(APP_LOCATION, 'resources'))
IMG_LOCATION = str(os.path.join(RES_LOCATION, 'images'))
FONT_LOCATION = str(os.path.join(RES_LOCATION, 'fonts'))
