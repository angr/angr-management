"""
monkeypatch_stdio - Monkeypatches stdout and stderr to be NullWriters.
"""

import sys


class NullWriter:  # pylint: disable=no-self-use,unused-argument
    """
    A file-like object that does nothing.
    """

    softspace = 0
    encoding = "UTF-8"

    def write(self, *args):
        pass

    def flush(self, *args):
        pass

    def isatty(self):
        return False


def monkeypatch_stdio():
    """
    Monkeypatch stdout and stderr to be NullWriters.
    """
    if sys.stdout is None:
        sys.stdout = NullWriter()
    if sys.stderr is None:
        sys.stderr = NullWriter()
