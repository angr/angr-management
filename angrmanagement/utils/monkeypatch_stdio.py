import sys


class NullWriter:
    softspace = 0
    encoding = 'UTF-8'

    def write(*args):
        pass

    def flush(*args):
        pass

    def isatty(self):
        return False

def monkeypatch_stdio():
    if sys.stdout is None:
        sys.stdout = NullWriter()
    if sys.stderr is None:
        sys.stderr = NullWriter()
