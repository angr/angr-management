"""
Test cases for reading the cart tool's configuration file.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import base64
import os
import tempfile
import unittest
from unittest.mock import patch

from angrmanagement.utils.cart_config import load_cart_config_key

KEY = b"\x02\xf53asdf\x00\x00\x00\x00\x00\x00\x00\x00\x00"


class TestLoadCartConfigKey(unittest.TestCase):
    """Test load_cart_config_key against the config formats the cart tool writes."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.path = os.path.join(self._dir.name, "cart.cfg")

    def tearDown(self) -> None:
        self._dir.cleanup()

    def _load(self, content: str | None) -> bytes | None:
        """Point the loader at a config file holding `content`, or at a missing file if None."""
        if content is not None:
            with open(self.path, "w", encoding="utf-8") as f:
                f.write(content)
        with patch("angrmanagement.utils.cart_config.os.path.expanduser", return_value=self.path):
            return load_cart_config_key()

    def test_reads_the_key(self) -> None:
        encoded = base64.b64encode(KEY).decode("ascii")
        assert self._load(f"[global]\nrc4_key = {encoded}\n") == KEY

    def test_ignores_other_options_and_sections(self) -> None:
        encoded = base64.b64encode(KEY).decode("ascii")
        content = f"[global]\ndelete = true\nrc4_key = {encoded}\n\n[header]\npoc = bob@organization\n"
        assert self._load(content) == KEY

    def test_missing_file(self) -> None:
        assert self._load(None) is None

    def test_empty_file(self) -> None:
        assert self._load("") is None

    def test_missing_section(self) -> None:
        assert self._load("[header]\npoc = bob@organization\n") is None

    def test_missing_option(self) -> None:
        assert self._load("[global]\ndelete = true\n") is None

    def test_empty_key(self) -> None:
        assert self._load("[global]\nrc4_key =\n") is None

    def test_malformed_config(self) -> None:
        assert self._load("this is not an ini file\n") is None

    def test_key_is_not_base64(self) -> None:
        assert self._load("[global]\nrc4_key = not!base64!\n") is None

    def test_unreadable_path(self) -> None:
        # a directory where a file is expected
        with patch("angrmanagement.utils.cart_config.os.path.expanduser", return_value=self._dir.name):
            assert load_cart_config_key() is None


if __name__ == "__main__":
    unittest.main(argv=[__file__])
