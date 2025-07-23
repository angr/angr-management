#!/bin/bash
set -e
cd "$(dirname "$0")"
cd ..

SRCDIR="$PWD/dist/angr-management"
if [[ ! -e $SRCDIR ]]; then
  echo "Run pyinstaller onedir build first"
  exit 1
fi

# Prepare AppDir
APPDIR="$PWD/appdir"
echo "[*] Preparing AppDir at $APPDIR"
mkdir -p $APPDIR/usr/bin
cp -r $SRCDIR/* $APPDIR/usr/bin/
for X in 16 24 32 64 128 256; do
  INDIR=$APPDIR/usr/bin/_internal/angrmanagement/resources/images
  OUTDIR=$APPDIR/usr/share/icons/hicolor/${X}x${X}/apps
  install -DT "${INDIR}/angr_${X}x${X}.png" "${OUTDIR}/angr-management.png"
done
install -DT angr-management.desktop $APPDIR/usr/share/applications/angr-management.desktop
install -DT angr-management.metainfo.xml $APPDIR/usr/share/metainfo/io.angr.angr-management.metainfo.xml

# Build AppImage
echo "[*] Building AppImage"

LINUXDEPLOY=linuxdeploy-$(uname -m).AppImage
if [[ ! -e $LINUXDEPLOY ]]; then
  echo "[>] Fetching linuxdeploy"
  wget --no-verbose https://github.com/linuxdeploy/linuxdeploy/releases/latest/download/$LINUXDEPLOY
  chmod +x *.AppImage
fi

LINUXDEPLOY_OUTPUT_VERSION=v$(python scripts/get-version.py) \
ARCH=$(uname -m) \
  ./$LINUXDEPLOY --appdir=$APPDIR --output appimage
