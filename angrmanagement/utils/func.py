from __future__ import annotations

from typing import TYPE_CHECKING

from angr.sim_type import SimType, SimTypePointer

if TYPE_CHECKING:
    from angr.knowledge_plugins import Function


def type2str(ty: SimType | None) -> str:
    """
    Convert a SimType instance to a string that can be displayed.

    :param ty:      The SimType instance, or None if it's for void.
    :return:        A string.
    """

    if ty is None:
        return "void"
    if isinstance(ty, SimTypePointer):
        return f"{type2str(ty.pts_to)}*"
    if ty.label:
        return ty.label
    return repr(ty)


def function_prototype_str(func: Function) -> str:
    if func.prototype is None:
        return func.name

    # Type of the return value
    s = ""
    rt = type2str(func.prototype.returnty)
    s += rt + " "

    # function name
    s += func.demangled_name
    s += "("

    # arguments
    for i, arg_type in enumerate(func.prototype.args):
        type_str = type2str(arg_type)

        if func.prototype.arg_names and i < len(func.prototype.arg_names):
            arg_name = func.prototype.arg_names[i]
        else:
            arg_name = "arg_%d" % i

        s += type_str + " " + arg_name

        if i < len(func.prototype.args) - 1:
            # splitter
            s += ","

    s += ")"
    return s
