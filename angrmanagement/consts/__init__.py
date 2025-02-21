from __future__ import annotations

import os

APP_LOCATION = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
PLUGIN_PATH = str(os.path.join(APP_LOCATION, "plugins"))
RES_LOCATION = str(os.path.join(APP_LOCATION, "resources"))
IMG_LOCATION = str(os.path.join(RES_LOCATION, "images"))
FONT_LOCATION = str(os.path.join(RES_LOCATION, "fonts"))
THEME_LOCATION = str(os.path.join(RES_LOCATION, "themes"))
