import pathlib
import sys

import angr
import capstone
import cle
import debugpy
import parso
import pypcode
import pyvex
import unicorn
import z3

sys.setrecursionlimit(sys.getrecursionlimit() * 5)

# Repo root
AM_BASE = pathlib.Path(SPECPATH)

# Python module roots
ANGR_BASE = pathlib.Path(angr.__file__).parent
CAPSTONE_BASE = pathlib.Path(capstone.__file__).parent
CLE_BASE = pathlib.Path(cle.__file__).parent
DEBUGPY_BASE = pathlib.Path(debugpy.__file__).parent
PARSO_BASE = pathlib.Path(parso.__file__).parent
PYPCODE_BASE = pathlib.Path(pypcode.__file__).parent
PYVEX_BASE = pathlib.Path(pyvex.__file__).parent
UNICORN_BASE = pathlib.Path(unicorn.__file__).parent
Z3_BASE = pathlib.Path(z3.__file__).parent

block_cipher = None
icon = str(AM_BASE / "angrmanagement" / "resources" / "images" / "angr.ico")

included_data = [
    (str(AM_BASE / "angrmanagement" / "resources"), "angrmanagement/resources"),
    (str(AM_BASE / "angrmanagement" / "resources" / "images"), "angrmanagement/resources/images"),
    (str(AM_BASE / "angrmanagement" / "plugins"), "angrmanagement/plugins"),
    (str(AM_BASE / "angrmanagement" / "config"), "angrmanagement/config"),
    (str(CLE_BASE / "backends" / "pe" / "relocation"), "cle/backends/pe/relocation"),
    (str(CLE_BASE / "backends" / "elf" / "relocation"), "cle/backends/elf/relocation"),
    (str(ANGR_BASE / "analyses" / "identifier" / "functions"), "angr/analyses/identifier/functions"),
    (str(ANGR_BASE / "procedures"), "angr/procedures"),
    (str(PARSO_BASE / "python"), "parso/python"),
    (str(AM_BASE / "flirt_signatures"), "flirt_signatures"),
    (str(AM_BASE / "library_docs"), "library_docs"),
    (str(DEBUGPY_BASE / "_vendored"), "debugpy/_vendored"),
    (str(PYPCODE_BASE / "processors"), "pypcode/processors"),
    (str(ANGR_BASE / "lib"), "angr/lib"),
    (str(PYVEX_BASE / "lib"), "pyvex/lib"),
    (str(UNICORN_BASE / "lib"), "unicorn/lib"),
    (str(CAPSTONE_BASE / "lib"), "capstone/lib"),
    (str(Z3_BASE / "lib"), "z3/lib"),
]


if sys.platform == "linux":
    import PySide6

    PYSIDE6_BASE = pathlib.Path(PySide6.__file__).parent
    included_data.append((str(PYSIDE6_BASE / "Qt" / "lib"), "PySide6/Qt/lib"))

    import archr
    import keystone

    ARCHR_BASE = pathlib.Path(archr.__file__).parent
    KEYSTONE_BASE = pathlib.Path(keystone.__file__).parent

    included_data.append((str(ARCHR_BASE / "implants"), "archr/implants"))
    included_data.append((str(KEYSTONE_BASE), "keystone"))

if sys.platform != "darwin":
    import zmq

    ZMQ_BASE = pathlib.Path(zmq.__file__).parent
    included_data.append((str(ZMQ_BASE / ".." / "pyzmq.libs"), "pyzmq.libs"))


a = Analysis(
    [str(AM_BASE / "start.py")],
    pathex=[],
    binaries=[],
    datas=included_data,
    hiddenimports=[
        "ipykernel.datapub",
        "pkg_resources.py2_warn",
        "sqlalchemy.sql.default_comparator",
        "pyxdg",
        "pyzmq",
        "xmlrpc.server",
        "charset_normalizer.md__mypyc",
        "PySide6.support.deprecated",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["debugpy"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="angr-management",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[icon],
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="angr-management",
)

if sys.platform == "darwin":
    app = BUNDLE(coll, name="angr-management.app", icon=icon, bundle_identifier=None)
