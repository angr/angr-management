"""What the Python console shows, whatever draws it: its namespace."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance


def base_namespace() -> dict[str, Any]:
    """The modules every console has: angr, claripy and cle."""
    import angr  # pylint: disable=import-outside-toplevel
    import cle  # pylint: disable=import-outside-toplevel

    # angr ships claripy as a subpackage
    return {"angr": angr, "claripy": importlib.import_module("angr.claripy"), "cle": cle}


def console_namespace(workspace, instance: Instance) -> dict[str, Any]:
    """The console's namespace: the modules, ``workspace``, ``instance`` and ``project``."""
    namespace = base_namespace()
    namespace.update({"workspace": workspace, "instance": instance, "project": instance.project})
    return namespace


def function_namespace(func) -> dict[str, Any]:
    """What the console gets when a function is shown: ``func`` and ``function`` (and the old ``function_``)."""
    return {"func": func, "function": func, "function_": func}
