# Run with: uv run check_windows_install.py <path to .exe or .zip>
#
# /// script
# dependencies = [
#   "pywinauto",
#   "psutil",
# ]
# ///
"""
Tests angr-management Windows installation stories.
"""
from __future__ import annotations

import argparse
import logging
import os
import os.path
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePath

if sys.platform == "win32":
    try:
        import winreg

        import psutil
        from pywinauto import Application
    except ImportError:
        print("Install psutil, pywinauto or run with `uv run`")
        sys.exit(1)
else:
    print("This script is intended only to be run on Windows")
    sys.exit(1)


log = logging.getLogger(__name__)


EXE_PATH_IN_ARCHIVE = PurePath("angr-management", "angr-management.exe")
INSTALLED_ROOT = Path(r"C:\Program Files") / "angr-management"
INSTALLED_EXE_PATH = INSTALLED_ROOT / "angr-management.exe"
UNINSTALLER_EXE_PATH = INSTALLED_ROOT / "uninstall.exe"
INSTALLED_FILE_PATHS = [
    INSTALLED_EXE_PATH,
    UNINSTALLER_EXE_PATH,
]
REG_KEY_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r"Software\angr-management"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall\angr-management"),
]
SHORTCUT_PATHS = [
    Path(os.environ["USERPROFILE"]) / "Desktop" / "angr-management.lnk",
    Path(os.environ["APPDATA"])
    / "Microsoft"
    / "Windows"
    / "Start Menu"
    / "Programs"
    / "angr-management"
    / "angr-management.lnk",
]

MAX_INSTALL_SECONDS = 5 * 60
MAX_UNINSTALL_SECONDS = 5 * 60
MAX_UNINSTALL_FILE_REMOVAL_WAIT_SECONDS = 15
MAX_TIME_TO_WELCOME_SECONDS = 15


def registry_key_exists(root: int, path: str) -> bool:
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ):
            return True
    except FileNotFoundError:
        return False


def kill_process_tree(pid, timeout: int = 5):
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            child.kill()
        parent.kill()

        _, alive = psutil.wait_procs([parent] + children, timeout=timeout)
        for p in alive:
            p.kill()
    except psutil.NoSuchProcess:
        pass


def run_silent_installer(installer_path: Path):
    assert is_not_installed()

    log.info("Installing...")
    start = time.time()
    with subprocess.Popen([installer_path, "/S"]) as process:
        process.wait(MAX_INSTALL_SECONDS)
    end = time.time()
    log.info("Installation took %.3f seconds", end - start)

    assert is_installed()


def is_installed() -> bool:
    return (
        all(path.exists() for path in INSTALLED_FILE_PATHS)
        and all(registry_key_exists(*path) for path in REG_KEY_PATHS)
        and all(path.exists() for path in SHORTCUT_PATHS)
    )


def is_not_installed() -> bool:
    return (
        all(not path.exists() for path in INSTALLED_FILE_PATHS)
        and all(not registry_key_exists(*path) for path in REG_KEY_PATHS)
        and all(not path.exists() for path in SHORTCUT_PATHS)
    )


def launch_and_wait_for_welcome_window(exe_path: Path):
    log.info("Launching...")
    start = time.time()
    app = Application().start(str(exe_path))
    try:
        app_window = app.window(title_re="Welcome - angr-management")
        app_window.wait("visible", timeout=MAX_TIME_TO_WELCOME_SECONDS)
        end = time.time()
        log.info("Welcome window detected after %.3f seconds", end - start)
    finally:
        kill_process_tree(app.process)


def run_silent_uninstaller():
    assert is_installed()

    log.info("Uninstalling...")
    with subprocess.Popen([UNINSTALLER_EXE_PATH, "/S"]) as process:
        process.wait(MAX_UNINSTALL_SECONDS)

    # Uninstaller may exit before the files are actually deleted. Wait a bit
    # before determining if uninstallation was successful.
    for _ in range(MAX_UNINSTALL_FILE_REMOVAL_WAIT_SECONDS):
        if is_not_installed():
            break
        log.info("Waiting for uninstallation cleanup...")
        time.sleep(1)

    assert is_not_installed()


def check_system_install_story(installer_path: Path):
    run_silent_installer(installer_path)
    launch_and_wait_for_welcome_window(INSTALLED_EXE_PATH)
    run_silent_uninstaller()


def check_portable_install_story(archive_path: Path):
    with tempfile.TemporaryDirectory() as temp_dir:
        log.info("Created temporary directory at: %s", temp_dir)

        log.info("Extracting...")
        start = time.time()
        shutil.unpack_archive(archive_path, temp_dir)
        end = time.time()
        log.info("Extraction took %.3f seconds", end - start)

        launch_and_wait_for_welcome_window(Path(temp_dir) / EXE_PATH_IN_ARCHIVE)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("file")
    args = ap.parse_args()

    file = Path(args.file)
    assert file.exists()

    match file.suffix.lower():
        case ".exe":
            check_system_install_story(file)
        case ".zip":
            check_portable_install_story(file)
        case _:
            log.info("Unhandled target file extension")
            sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
