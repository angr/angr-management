from __future__ import annotations

import base64
import binascii
import configparser
import logging
import os

_l = logging.getLogger(__name__)


# where the cart command-line tool keeps its settings; see cart.cart.main()
CART_CONFIG_PATH = os.path.join("~", ".cart", "cart.cfg")
CART_CONFIG_SECTION = "global"
CART_CONFIG_KEY_OPTION = "rc4_key"


def load_cart_config_key() -> bytes | None:
    """
    Read the default ARC4 key out of the cart tool's configuration file.

    cle does not consult this file: it passes arc4_key=None to the cart library, which then falls back to the library's
    own built-in key. We read it only to suggest a key to the user.

    :return:    The key, or None if the file is absent or does not hold a usable one.
    """
    path = os.path.expanduser(CART_CONFIG_PATH)

    config = configparser.ConfigParser()
    try:
        if not config.read(path):
            return None
        encoded = config.get(CART_CONFIG_SECTION, CART_CONFIG_KEY_OPTION)
    except (configparser.Error, OSError, UnicodeDecodeError):
        _l.debug("Cannot read the cart configuration file %s.", path, exc_info=True)
        return None

    try:
        key = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        _l.debug("%s in %s is not a valid Base64 string.", CART_CONFIG_KEY_OPTION, path)
        return None

    return key or None
