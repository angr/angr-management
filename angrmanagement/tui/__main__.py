"""Entry point of the ``am-tui`` command."""

from __future__ import annotations

import sys


def main() -> int:
    """Report that the terminal frontend is not available yet and exit with status 2."""
    print("am-tui: the terminal frontend of angr management is not implemented yet.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
