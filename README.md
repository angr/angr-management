# angr-management

This is the GUI for angr.
Launch it and analyze some binaries!

## Installation

To install angr-management, use pip:

```
pip install PySide --install-option "--jobs=4"  # replace 4 with the number of cores on your machine
pip install angr-management
```
## How to run

To run angr-management:

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

