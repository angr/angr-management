#!/bin/bash
set -ex

python -m venv .venv
if [[ "$OSTYPE" == "msys" ]]; then
    source .venv/Scripts/activate
else
    source .venv/bin/activate
fi

# Install dependencies

python -m pip install -U pip wheel setuptools unicorn==2.0.1.post1

# TODO: remove this when upstream packaging is fixed, extra is added to cle
pip install git+https://github.com/theopolis/uefi-firmware-parser.git

pip install git+https://github.com/eliben/pyelftools.git
pip install git+https://github.com/angr/archinfo.git
pip install git+https://github.com/angr/pyvex.git
pip install git+https://github.com/angr/cle.git
pip install git+https://github.com/angr/claripy.git
pip install git+https://github.com/angr/ailment.git
pip install --no-build-isolation git+https://github.com/angr/angr.git#egg=angr[pcode]
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    pip install git+https://github.com/angr/archr.git#egg=archr
fi

# Install angr-mangement
pip install -e .[pyinstaller]

# Bundle!
pyinstaller angr-management.spec

mkdir upload

# Prepare onedirs
if [[ "$OSTYPE" == "darwin"* ]]; then
    mkdir /tmp/angr-management-dmg
    cp -r dist/*.app /tmp/angr-management-dmg
    hdiutil create upload/angr-management-macOS.dmg -volname "angr-management nightly" -srcfolder /tmp/angr-management-dmg
elif [[ "$OSTYPE" == "linux-gnu" ]]; then
    source /etc/os-release
    tar -C dist -czf upload/angr-management-$ID-$VERSION_ID.tar.gz angr-management
elif [[ "$OSTYPE" == "msys" ]]; then
    OUTDIR=$(pwd)/upload
    pushd dist
    7z a $OUTDIR/angr-management-win64.zip \*
    popd
fi
