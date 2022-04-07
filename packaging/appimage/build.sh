#!/bin/bash
set -ex

BASE_DIR=$(dirname $(dirname $(dirname $(realpath "$0"))))
APPDIR=$BASE_DIR/packaging/appimage/AppDir

rm -rf $APPDIR
mkdir -p $APPDIR/opt
mkdir -p $APPDIR/usr/share/icons

# First build the pyinstall onedir
python $BASE_DIR/packaging/pyinstaller/bundle.py

# Copy out build artifact
cp -r $BASE_DIR/packaging/pyinstaller/onedir/angr-management $APPDIR/opt/
# Copy icon
cp $BASE_DIR/angrmanagement/resources/images/angr.png $APPDIR/usr/share/icons/angr200x200.png

pushd $BASE_DIR/packaging/appimage
appimage-builder --skip-tests
popd
