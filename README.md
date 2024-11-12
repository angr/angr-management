# angr Management
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

This is the GUI for angr.
Launch it and analyze some binaries!

Some screenshots:

[![Disassembly](screenshots/disassembly.png)](https://github.com/angr/angr-management/blob/master/screenshots/disassembly.png)
[![Decompilation](screenshots/decompilation.png)](https://github.com/angr/angr-management/blob/master/screenshots/decompilation.png)

## Usage

## Configuration

Configuration files locations vary by platform.

- Windows: `~\AppData\Local\angr-management\config.toml`
- macOS: `~/Library/Preferences/angr-management/config.toml`
- Linux: `~/.config/angr-management/config.toml`

## Building with PyInstaller
To build a portable executable using PyInstaller, install angr management into a python envrionment with the `pyinstaller` extra.
Do not install anything in editable mode (pip's `-e`), as PyInstaller currently [fails to bundle](https://github.com/pyinstaller/pyinstaller/issues/7524) modules installed with editable mode.
Then, run `pyinstaller angr-management.spec`.

If things go wrong, the best bet is to reference the nightly build pipeline and the [PyInstaller docs](https://pyinstaller.org/en/stable/).
The CI environment that produces nightly builds is at `.github/workflows/nightly-build.yml` and `.github/workflows/nightly-build.sh`.
