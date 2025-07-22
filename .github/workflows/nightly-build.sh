#!/bin/bash
set -ex

uv sync --python "3.12" --extra pyinstaller --extra binharness

# Bundle!
uv run pyinstaller angr-management.spec

mkdir upload

# Prepare onedirs
if [[ "$OSTYPE" == "darwin"* ]]; then
    mkdir /tmp/angr-management-zip
    ZIP_PATH=$(pwd)/upload/angr-management-macOS-$(uname -m).zip
    pushd dist
    zip -ry $ZIP_PATH *.app
    popd
elif [[ "$OSTYPE" == "linux-gnu" ]]; then
    source /etc/os-release
    tar -C dist -czf upload/angr-management-$ID-$VERSION_ID-$(uname -m).tar.gz angr-management
elif [[ "$OSTYPE" == "msys" ]]; then
    OUTDIR=$(pwd)/upload
    pushd dist
    7z a $OUTDIR/angr-management-win64.zip \*
    popd

    # Build Windows installer
    makensis \
        -DVERSION=$(python scripts/get-version.py) \
        -DPRODUCT_VERSION=$(python scripts/get-version.py --format numeric) \
        angr-management.nsi
    mv *.exe $OUTDIR
fi
