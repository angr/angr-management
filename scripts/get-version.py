from __future__ import annotations

import argparse
import pathlib
import re


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--format", choices=["pep440", "numeric"], default="pep440")
    args = ap.parse_args()

    # Get version number from angrmanagement/__init__.py __version__ string
    path = pathlib.Path(__file__).parent.parent / "angrmanagement" / "__init__.py"
    content = path.read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', content, re.MULTILINE)
    if not match:
        raise RuntimeError("Version string not found")
    version = match.group(1)

    if args.format == "numeric":
        # Transform devX prefix into 9000+X
        version = list(version.split("."))
        if version[-1].startswith("dev"):
            version[-1] = str(9000 + int(version[-1].removeprefix("dev")))
        while len(version) < 4:
            version.append("0")
        version = ".".join(version)

    print(version)


if __name__ == "__main__":
    main()
