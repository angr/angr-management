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
    pip install "appimage-builder>=1.0.0a2"
    pip install keystone-engine
    pip install git+https://github.com/angr/archr.git#egg=archr
fi

# Install angr-mangement
pip install -e .

# Bundle!
python packaging/pyinstaller/bundle.py --onefile
python packaging/pyinstaller/bundle.py --onedir
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    bash packaging/appimage/build.sh
fi

mkdir upload

# Prepare onefiles
ONEFILE_DIR=packaging/onefile
if [[ "$OSTYPE" == "darwin"* ]]; then
    cp $ONEFILE_DIR/angr-management upload/angr-management-onefile-macos
elif [[ "$OSTYPE" == "linux-gnu" ]]; then
    cp $ONEFILE_DIR/angr-management upload/angr-management-onefile-ubuntu
else
    cp $ONEFILE_DIR/angr-management.exe upload/angr-management-onefile-win64.exe
fi

# Prepare onedirs
ONEDIR_DIR=packaging/onedir
if [[ "$OSTYPE" == "darwin"* ]]; then
    hdiutil create upload/angr-management-macOS.dmg -volname "angr-management nightly" -srcfolder $ONEDIR_DIR
elif [[ "$OSTYPE" == "linux-gnu" ]]; then
    tar -C $ONEDIR_DIR -czf upload/angr-management-ubuntu.tar.gz angr-management
else
    7z a upload/angr-management-win64.zip $ONEDIR_DIR/\*
fi

# Prepare appimage
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    cp packaging/appimage/angr management-latest-x86_64.AppImage upload/angr-management.AppImage
fi
