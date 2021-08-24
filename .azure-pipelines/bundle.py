#!/usr/bin/env python3

import sys
import os

# for finding various libs
import angrmanagement
import capstone
import unicorn
import pyvex
import angr
import cle
import z3
import zmq
import parso

if sys.platform == "linux":
    import archr


def make_common_options(for_chess=False):
    """
    Create the pyinstaller command.
    """

    # any dynamically-loaded modules have to be explicitly added
    included_data = [
        (
            os.path.join(os.path.dirname(angrmanagement.__file__), "resources"),
            "angrmanagement/resources",
        ),
        (
            os.path.join(os.path.dirname(angrmanagement.__file__), "resources/images"),
            "angrmanagement/resources/images",
        ),
        (
            os.path.join(os.path.dirname(angrmanagement.__file__), "plugins"),
            "angrmanagement/plugins",
        ),
        (
            os.path.join(os.path.dirname(angrmanagement.__file__), "config"),
            "angrmanagement/config",
        ),
        (
            os.path.join(os.path.dirname(cle.__file__), "backends/pe/relocation"),
            "cle/backends/pe/relocation",
        ),
        (
            os.path.join(os.path.dirname(cle.__file__), "backends/elf/relocation"),
            "cle/backends/elf/relocation",
        ),
        (
            os.path.join(
                os.path.dirname(angr.__file__), "analyses/identifier/functions"
            ),
            "angr/analyses/identifier/functions",
        ),
        (os.path.join(os.path.dirname(angr.__file__), "procedures"), "angr/procedures"),
        (os.path.join(os.path.dirname(parso.__file__), "python"), "parso/python"),
    ]
    if for_chess:
        repo_dir = os.path.dirname(os.path.dirname(angrmanagement.__file__))
        included_data.append(
            (
                os.path.join(repo_dir, "flirt_signatures"),
                "flirt_signatures"
            )
        )
        included_data.append(
            (
                os.path.join(repo_dir, "library_docs"),
                "library_docs"
            )
        )
    if sys.platform == "linux":
        included_data.append(
            (
                os.path.join(os.path.dirname(archr.__file__), "implants"),
                "archr/implants",
            )
        )
    if sys.platform != "darwin":
        included_data.append(
            (
                os.path.join(os.path.dirname(zmq.__file__), os.pardir, "pyzmq.libs"),
                "pyzmq.libs",
            )
        )

    # dynamically-loaded DLLs have to be explicitly added. We just include the entire lib dir.
    included_libs = [
        (os.path.join(os.path.dirname(angr.__file__), "lib"), "angr/lib"),
        (os.path.join(os.path.dirname(pyvex.__file__), "lib"), "pyvex/lib"),
        (os.path.join(os.path.dirname(unicorn.__file__), "lib"), "unicorn/lib"),
        (capstone._path, "capstone/lib"),
        (os.path.join(os.path.dirname(z3.__file__), "lib"), "z3/lib"),
    ]

    if sys.platform == "linux":
        import keystone
        included_libs.append((os.path.dirname(keystone.__file__), "keystone"))

    all_mappings = [
        (";" if sys.platform.startswith("win") else ":").join(mapping)
        for mapping in (included_data + included_libs)
    ]

    # include ipython because it's not autodetected for some reason
    hidden_import = [
        "--hidden-import=ipykernel.datapub",
        "--hidden-import=pkg_resources.py2_warn",
        "--hidden-import=sqlalchemy.sql.default_comparator",
        "--hidden-import=pyxdg",
        "--hidden-import=pyzmq",
    ]
    if for_chess:
        hidden_import.append("--hidden-import=slacrs")
        hidden_import.append("--hidden-import=getmac")
        hidden_import.append("--hidden-import=qtterm")
    args = [
        "pyinstaller",
        ] + hidden_import + [
        "--name=angr-management",
        "-w",
        "-i",
        os.path.join(
            os.path.dirname(angrmanagement.__file__), "resources", "images", "angr.ico"
        ),
    ]

    for mapping in all_mappings:
        args.append("--add-data")
        args.append(mapping)
    args.append("start.py")

    return args


def make_bundle(onefile=True, for_chess=False):
    """
    Execute the pyinstaller command.
    """
    args = make_common_options(for_chess=for_chess)

    if onefile:
        args.append("--onefile")
        args.append("--distpath")
        args.append("onefile")

    if sys.platform in ("linux", "win32", "darwin"):
        print(f"Creating bundle for {sys.platform}")
        os.system(" ".join(args))
    else:
        print(f"Unsupported platform: {sys.platform}")


def main():
    for_chess = "--chess" in sys.argv
    if "--onefile" in sys.argv:
        make_bundle(onefile=True, for_chess=for_chess)
    if "--onedir" in sys.argv:
        make_bundle(onefile=False, for_chess=for_chess)


if __name__ == "__main__":
    main()
