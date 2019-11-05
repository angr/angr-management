#!/bin/bash -e

# Install dependencies

# Install unicorn from git only on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    pip install git+git://github.com/twizmwazin/unicorn.git@msbuild-windows-only#subdirectory=bindings/python&egg=unicorn
fi
pip install pyinstaller
pip install git+https://github.com/angr/archinfo.git#egg=archinfo
pip install git+https://github.com/angr/pyvex.git@platform-specific-build#egg=pyvex
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
python bundle.py

# Binary is currently at dist/start
