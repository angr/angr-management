#!/bin/bash
set -ex

python -m venv .venv
if [[ "$OSTYPE" == "msys" ]]; then
    source .venv/Scripts/activate
else
    source .venv/bin/activate
fi

if [[ "$OSTYPE" == "darwin"* && "$(uname -m)" == "arm64" ]]; then
    EXTRA_ANGR_INSTALL_ARGS="--no-binary capstone"
else
    EXTRA_ANGR_INSTALL_ARGS=""
fi


# Install dependencies

python -m pip install -U pip wheel setuptools unicorn==2.0.1.post1

pip install git+https://github.com/eliben/pyelftools.git
pip install git+https://github.com/angr/archinfo.git
pip install git+https://github.com/angr/pyvex.git
pip install git+https://github.com/angr/cle.git#egg=cle[ar,minidump,uefi,xbe]
pip install git+https://github.com/angr/claripy.git
pip install git+https://github.com/angr/ailment.git
pip install $EXTRA_ANGR_INSTALL_ARGS --no-build-isolation git+https://github.com/angr/angr.git#egg=angr[pcode]
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
    mkdir /tmp/angr-management-zip
    cp -r dist/*.app /tmp/angr-management-zip
    zip -r upload/angr-management-macOS-$(uname -m).zip /tmp/angr-management-zip
elif [[ "$OSTYPE" == "linux-gnu" ]]; then
    source /etc/os-release
    tar -C dist -czf upload/angr-management-$ID-$VERSION_ID.tar.gz angr-management
elif [[ "$OSTYPE" == "msys" ]]; then
    OUTDIR=$(pwd)/upload
    pushd dist
    7z a $OUTDIR/angr-management-win64.zip \*
    popd
fi
