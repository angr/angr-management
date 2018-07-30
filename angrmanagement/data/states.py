
import logging

l = logging.getLogger('data.states')


class StateRecord(object):

    BLANK_STATE = 'blank_state'
    ENTRY_STATE = 'entry_state'
    FULL_INIT_STATE = 'full_init_state'

    def __init__(self, name, base_state, is_default, mode, custom_options=None, address=None, custom_code=None):

        if base_state not in {self.BLANK_STATE, self.ENTRY_STATE, self.FULL_INIT_STATE} and \
                not isinstance(base_state, StateRecord):
            l.warning('Unknown base state type "%s". Default to blank_state.', base_state)
            base_state = self.BLANK_STATE

        self.name = name
        self.base_state = base_state
        self.is_default = is_default
        self.mode = mode
        self.address = address
        self.custom_options = custom_options
        self.custom_code = custom_code

    def state(self, project, address=None):
        if self.base_state == self.BLANK_STATE:
            s = project.factory.blank_state(addr=address)
        elif self.base_state == self.ENTRY_STATE:
            s = project.factory.entry_state(addr=address)
        elif self.base_state == self.FULL_INIT_STATE:
            s = project.factory.full_init_state(addr=address)
        elif isinstance(self.base_state, StateRecord):
            s = self.base_state.state(project, address=address).copy()
        else:
            raise Exception()

        if self.custom_options:
            s.options.clear()
            s.options |= self.custom_options

        if self.custom_code:
            custom_code = self.custom_code + "\n\ns = init_state(s)"
            exec(custom_code)  # s will be updated

        return s

    @classmethod
    def basics(cls):
        return [
            cls('Blank State', StateRecord.BLANK_STATE, True, 'symbolic'),
            cls('Entry State', StateRecord.ENTRY_STATE, True, 'symbolic'),
            cls('Full-init State', StateRecord.FULL_INIT_STATE, True, 'symbolic'),
        ]
