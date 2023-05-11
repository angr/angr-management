import os
import pathlib

import PyInstaller.__main__

os.chdir(pathlib.Path(__file__).parent)

common_args = [
    "--noconfirm",
    str(pathlib.Path(__file__).parent / "angr-management.spec"),
    "--workpath",
    "build",
    "--distpath",
    "dist",
]
PyInstaller.__main__.run([*common_args])
