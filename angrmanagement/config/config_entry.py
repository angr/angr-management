
class ConfigurationEntry(object):

    __slots__ = ['name', 'type_', 'value', 'default_value']

    def __init__(self, name, type_, value, default_value=None):
        self.name = name
        self.type_ = type_
        self.value = value
        self.default_value = default_value

    def copy(self):
        return ConfigurationEntry(self.name, self.type_, self.value, default_value=self.default_value)
