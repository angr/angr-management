"""Entry point of the ``am-tui`` command."""

from __future__ import annotations

import importlib
import sys


def main() -> int:
    """Report that the terminal frontend is not available yet, or that its dependencies are missing; exit with 2."""
    try:
        importlib.import_module("textual")
    except ImportError:
        print(
            "am-tui: the terminal frontend needs Textual; install it with: pip install 'angr-management[tui]'",
            file=sys.stderr,
        )
        return 2
    print("am-tui: the terminal frontend of angr management is not implemented yet.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
