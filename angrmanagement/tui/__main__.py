"""Entry point of the ``am-tui`` command."""

from __future__ import annotations

import argparse
import asyncio
import importlib
import os
import sys


def parse_size(text: str) -> tuple[int, int]:
    """``"200x60"`` is 200 columns by 60 rows."""
    cols, _, rows = text.lower().partition("x")
    try:
        size = int(cols), int(rows)
    except ValueError as ex:
        raise argparse.ArgumentTypeError(f"not COLSxROWS: {text!r}") from ex
    if size[0] < 20 or size[1] < 5:
        raise argparse.ArgumentTypeError(f"too small: {text!r}")
    return size


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="am-tui", description="angr management in a terminal.")
    parser.add_argument("binary", nargs="?", help="the binary, angr database or trace to open")
    parser.add_argument("--config-dir", help="read and save the configuration in this directory")
    parser.add_argument(
        "--theme",
        help="the colour scheme: Light, Dark, Dracula, Catppuccin Mocha or Custom (the configured one by default)",
    )
    parser.add_argument("--size", type=parse_size, help="the screen size, COLSxROWS (the terminal's by default)")
    parser.add_argument(
        "--screenshot-dir",
        help="do not run interactively: open the binary, save an SVG screenshot of every view here, and exit",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the terminal frontend; returns the exit status."""
    args = parse_args(argv)
    if args.config_dir:
        os.environ["ANGR_MANAGEMENT_CONFIG_DIR"] = os.path.abspath(args.config_dir)
    try:
        importlib.import_module("textual")
    except ImportError:
        print(
            "am-tui: the terminal frontend needs Textual; reinstall angr management, or: pip install textual",
            file=sys.stderr,
        )
        return 2

    # pylint:disable=import-outside-toplevel
    from angrmanagement.tui.caps import detect

    if args.screenshot_dir:
        from angrmanagement.tui.screenshot import shoot

        written = asyncio.run(shoot(args.screenshot_dir, args.binary, args.size or (200, 60), theme_name=args.theme))
        for path in written:
            print(path)
        return 0

    from angrmanagement.tui.app import AmApp

    # the terminal is asked what it can do before Textual reads its input
    caps = detect(probe=True)
    app = AmApp(binary=args.binary, caps=caps, theme_name=args.theme)
    app.run(size=args.size)
    return app.return_code or 0


if __name__ == "__main__":
    sys.exit(main())
