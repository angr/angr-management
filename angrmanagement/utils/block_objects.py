

class FunctionHeader:

    __slots__ = ('name', 'prototype', 'args', 'io_params', )

    def __init__(self, name, prototype=None, args=None, io_params=None):
        self.name = name
        self.prototype = prototype
        self.args = args
        self.io_params = io_params


class Variables:

    __slots__ = ['variables']

    def __init__(self, variables):
        self.variables = variables


class PhiVariable(Variables):

    __slots__ = ['variable']

    def __init__(self, variable, variables):
        super().__init__(variables)
        self.variable = variable


class Label:

    __slots__ = ['addr', 'text']

    def __init__(self, addr, text):
        self.addr = addr
        self.text = text
