#!/bin/bash -ex

# Install dependencies

function install_repo() {
    repo=$1
    name=$(cut -d'/' -f 2)
    mkdir -p repos
    git clone https://github.com/$repo repos/$name
    pip install -e repos/$name
}

pip install wheel
pip install pyinstaller
install_repo eliben/pyelftools
install_repo angr/archinfo
install_repo angr/pyvex
install_repo angr/cle
install_repo angr/claripy
install_repo angr/ailment
install_repo angr/angr
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    pip install keystone-engine --no-binary keystone-engine
    install_repo angr/archr
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
