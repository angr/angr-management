Building with PyInstaller
-------------------------
To build a portable executable using PyInstaller, install angr management into a python envrionment with the :code:`pyinstaller` extra.
Do not install anything in editable mode (pip's :code:`-e`), as PyInstaller currently `fails to bundle <https://github.com/pyinstaller/pyinstaller/issues/7524>`_ modules installed with editable mode.
Then, run :code:`pyinstaller angr-management.spec`.

If things go wrong, the best bet is to reference the nightly build pipeline and the `PyInstaller docs <https://pyinstaller.org/en/stable/>`_.
The CI environment that produces nightly builds is at :code:`.github/workflows/nightly-build.yml` and :code:`.github/workflows/nightly-build.sh`.
