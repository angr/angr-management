#!/usr/bin/env python3

import multiprocessing

from angrmanagement.__main__ import main


if __name__ == '__main__':
    multiprocessing.freeze_support()
    main()
