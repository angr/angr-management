# angr Management

This is the GUI for angr.
Launch it and analyze some binaries!

## Installation

### From PyPI

To install angr-management, use pip:

```
pip install PySide --install-option "--jobs=4"  # replace 4 with the number of cores on your machine
pip install angr-management
```

The version on PyPI may not be up-to-date.
Please consider having a development install if you plan to use latest features/fixes in angr Management.

### Development Install

- Check out the Git repo:

```
git clone git@github.com:angr/angr-management.git
```

- Install PySide

```
pip install PySide --install-option "--jobs=4"  # replace 4 with the number of cores on your machine
```

- Install angr Management

```
cd angr-management
pip install -e .
```

## How to run

To run angr-management:

```
python -m angrmanagement
```

Or if you have a development install:

```
python start.py
```

## Issues

### 'module' object has noattribute 'MIPS_GRP_CALL'

Your capstone install does not support functionality that angr-management uses.

To install a version that does (in your angr virtualenv):
```
workon angr
git clone https://github.com/angr/capstone
cd capstone
git checkout next
./make.sh
PACKAGES_PATH=$(python -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")
mkdir -p $PACKAGES_PATH/capstone
cp libcapstone.so.4 $PACKAGES_PATH/capstone/libcapstone.so
cd bindings/python
pip uninstall capstone  # if already installed
python setup.py install
```

