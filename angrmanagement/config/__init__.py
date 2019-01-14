
import os

from .config_manager import ConfigurationManager

# Global configuration manager instance
Conf = ConfigurationManager()

APP_LOCATION = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
RES_LOCATION = str(os.path.join(APP_LOCATION, 'resources'))
IMG_LOCATION = str(os.path.join(RES_LOCATION, 'images'))
FONT_LOCATION = str(os.path.join(RES_LOCATION, 'fonts'))
