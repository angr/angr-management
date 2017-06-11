

class Variables(object):

    __slots__ = ['variables']

    def __init__(self, variables):
        self.variables = variables


class Label(object):

    __slots__ = ['addr', 'text']

    def __init__(self, addr, text):
        self.addr = addr
        self.text = text
