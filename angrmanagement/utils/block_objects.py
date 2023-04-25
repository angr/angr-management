class FunctionHeader:
    __slots__ = (
        "name",
        "prototype",
        "args",
    )

    def __init__(self, name, prototype=None, args=None):
        self.name = name
        self.prototype = prototype
        self.args = args


class Variables:
    __slots__ = ["variables"]

    def __init__(self, variables):
        self.variables = variables


class PhiVariable(Variables):
    __slots__ = ["variable"]

    def __init__(self, variable, variables):
        super().__init__(variables)
        self.variable = variable


class Label:
    __slots__ = ["addr", "text"]

    def __init__(self, addr, text):
        self.addr = addr
        self.text = text
