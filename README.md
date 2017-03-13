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

### ImportError: ... undefined symbol: Agundirected

`pygraphviz` is not compiled correctly.
See [stackoverflow](http://stackoverflow.com/questions/32885486/pygraphviz-importerror-undefined-symbol-agundirected) and [GitHub issue](https://github.com/pygraphviz/pygraphviz/issues/71).

### 'module' object has noattribute 'MIPS_GRP_CALL'

Your capstone install is too old.
You may install the version from [our fork](https://github.com/angr/capstone).

