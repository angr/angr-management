#!/bin/bash -e

python -m venv .venv
source .venv/bin/activate

# Install dependencies

pip install -U pip wheel pyinstaller
pip install git+https://github.com/eliben/pyelftools#egg=pyelftools
pip install git+https://github.com/angr/archinfo.git#egg=archinfo
pip install git+https://github.com/angr/pyvex.git#egg=pyvex
pip install git+https://github.com/angr/cle.git#egg=cle
pip install git+https://github.com/angr/claripy.git#egg=claripy
pip install git+https://github.com/angr/ailment.git#egg=ailment
pip install git+https://github.com/angr/angr.git#egg=angr
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    pip install keystone-engine
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
elif [[ "$OSTYPE" == "linux-gnu" ]]; then
    cp onefile/angr-management upload/angr-management-onefile-ubuntu
else
    mv onefile/angr-management.exe upload/angr-management-onefile-win64.exe
fi

# Prepare onedirs
if [[ "$OSTYPE" == "darwin"* ]]; then
    rm -rf dist/angr-management
    hdiutil create upload/angr-management-macOS.dmg -volname "angr-management nightly" -srcfolder dist
elif [[ "$OSTYPE" == "linux-gnu" ]]; then
    tar -C dist -czf upload/angr-management-ubuntu.tar.gz angr-management
else
    7z a upload/angr-management-win64.zip ./dist/\*
fi
