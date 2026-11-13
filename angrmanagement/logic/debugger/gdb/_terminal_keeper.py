"""Hold a detached inferior's terminal until its original process exits.

Run directly in a separate interpreter: it must not import the application or
depend on its threads surviving shutdown. A pidfd avoids PID reuse races.
"""

from __future__ import annotations

import errno
import os
import select
import sys


def main() -> None:
    master, pidfd = (int(value) for value in sys.argv[1:])
    try:
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        poller.register(master, select.POLLIN)
        os.write(1, b"R")
        os.close(1)
        while True:
            ready = poller.poll()
            if any(descriptor == pidfd for descriptor, _ in ready):
                return
            for _, events in ready:
                if events & select.POLLNVAL:
                    raise OSError(errno.EBADF, "Detached target terminal descriptor is invalid")
                retry = bool(events & (select.POLLHUP | select.POLLERR))
                if events & select.POLLIN:
                    try:
                        retry = not os.read(master, 65536) or retry
                    except BlockingIOError:
                        pass
                    except OSError as exc:
                        if exc.errno != errno.EIO:
                            raise
                        retry = True
                if retry:
                    # HUP stays ready while no slave exists. Wait on the pidfd
                    # alone before retrying, so reopening resumes draining without
                    # an idle spin or delaying target-exit detection.
                    poller.unregister(master)
                    if poller.poll(100):
                        return
                    poller.register(master, select.POLLIN)
    finally:
        os.close(master)
        os.close(pidfd)


if __name__ == "__main__":
    main()
