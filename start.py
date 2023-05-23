#!/usr/bin/env python3

import multiprocessing

from angrmanagement.__main__ import main
from angrmanagement.utils.monkeypatch_stdio import monkeypatch_stdio

if __name__ == "__main__":
    multiprocessing.freeze_support()
    monkeypatch_stdio()
    main()
