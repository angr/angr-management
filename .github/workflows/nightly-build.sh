#!/bin/bash
set -ex

# Optional tag to install from. Default is master.
TAG=${1:-master}

python -m venv .venv
if [[ "$OSTYPE" == "msys" ]]; then
    source .venv/Scripts/activate
else
    source .venv/bin/activate
fi

# Install dependencies

python -m pip install -U pip wheel setuptools setuptools-rust unicorn==2.0.1.post1

pip install git+https://github.com/eliben/pyelftools.git
pip install git+https://github.com/angr/archinfo.git@$TAG
pip install git+https://github.com/angr/pyvex.git@$TAG
pip install git+https://github.com/angr/cle.git@$TAG#egg=cle[ar,minidump,uefi,xbe,pdb]
pip install git+https://github.com/angr/claripy.git@$TAG
pip install --no-build-isolation git+https://github.com/angr/angr.git@$TAG#egg=angr[pcode]
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    pip install git+https://github.com/angr/archr.git@$TAG
fi

# Install angr-mangement
pip install -e .[pyinstaller,binharness]

# Bundle!
pyinstaller angr-management.spec

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
    tar -C dist -czf upload/angr-management-$ID-$VERSION_ID.tar.gz angr-management
elif [[ "$OSTYPE" == "msys" ]]; then
    OUTDIR=$(pwd)/upload
    pushd dist
    7z a $OUTDIR/angr-management-win64.zip \*
    popd
fi
