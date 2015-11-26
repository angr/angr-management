from angr.functionmanager import Function

from atom.api import Atom, Dict, Typed, Value


class FunctionEntry(Atom):
    function = Typed(Function)

    def __str__(self):
        return self.function.name


class CodeAddressEntry(Atom):
    address = Value()

    def __str__(self):
        return 'loc_%x' % self.address


class Registry(Atom):
    offsets = Dict()

    # def stringify(self, value):
    #     if value in self.offsets:
    #         return str(self.offsets[value])
    #     elif
