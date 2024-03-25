from __future__ import annotations


class FunctionHeader:
    __slots__ = (
        "name",
        "prototype",
        "args",
    )

    def __init__(self, name: str, prototype=None, args=None) -> None:
        self.name = name
        self.prototype = prototype
        self.args = args


class Variables:
    __slots__ = ["variables"]

    def __init__(self, variables) -> None:
        self.variables = variables


class PhiVariable(Variables):
    __slots__ = ["variable"]

    def __init__(self, variable, variables) -> None:
        super().__init__(variables)
        self.variable = variable


class Label:
    __slots__ = ["addr", "text"]

    def __init__(self, addr: int, text: str) -> None:
        self.addr = addr
        self.text = text
