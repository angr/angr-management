#!/bin/bash -e

# Install dependencies

pip install wheel
pip install pyinstaller
pip install git+https://github.com/eliben/pyelftools#egg=pyelftools
pip install git+https://github.com/angr/archinfo.git#egg=archinfo
pip install git+https://github.com/angr/pyvex.git#egg=pyvex
pip install git+https://github.com/angr/cle.git#egg=cle
pip install git+https://github.com/angr/claripy.git#egg=claripy
pip install git+https://github.com/angr/ailment.git#egg=ailment
pip install git+https://github.com/angr/angr.git#egg=angr
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    pip install keystone-engine --no-binary keystone-engine
    pip install git+https://github.com/angr/archr.git#egg=archr
fi

# Install angr-mangement
pip install -e .

# Bundle!
python .azure-pipelines/bundle.py --onefile
python .azure-pipelines/bundle.py --onedir

mkdir upload

# Prepare onefiles
if [[ "$OSTYPE" == "darwin"* ]]; then
    cp onefile/angr-management upload/angr-management-onefile-macos
else
    cp onefile/angr-management upload/angr-management-onefile-ubuntu
fi

# Prepare onedirs
if [[ "$OSTYPE" == "darwin"* ]]; then
    rm -rf dist/angr-management
    hdiutil create upload/angr-management-macOS.dmg -volname "angr-management nightly" -srcfolder dist
else
    tar -C dist -czf upload/angr-management-ubuntu.tar.gz angr-management
fi
