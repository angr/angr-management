
import logging

l = logging.getLogger('data.states')


class StateRecord(object):

    BLANK_STATE = 'blank_state'
    ENTRY_STATE = 'entry_state'
    FULL_INIT_STATE = 'full_init_state'

    def __init__(self, name, base_state, is_default, mode, custom_options=None, address=None, custom_code=None):

        if base_state not in {self.BLANK_STATE, self.ENTRY_STATE, self.FULL_INIT_STATE}:
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
        else:
            raise Exception()

        if self.custom_options:
            s.options.clear()
            s.options |= self.custom_options

        if self.custom_code:
            raise Exception('Custom code is not yet supported.')

        return s


class StateManager(object):
    def __init__(self, instance, project):

        self.instance = instance
        self.project = project

        self._name_to_state_records = { }  # name to state records
        self._state_records = [ ]

        self['Blank State'] = StateRecord('Blank State', StateRecord.BLANK_STATE, True, 'symbolic')
        self['Entry State'] = StateRecord('Entry State', StateRecord.ENTRY_STATE, True, 'symbolic')
        self['Full Initial State'] = StateRecord('Full Initial State', StateRecord.FULL_INIT_STATE, True, 'symbolic')

    def __delitem__(self, name):
        if name in self._name_to_state_records and not self._name_to_state_records[name].is_default:
            del self._name_to_state_records[name]
            self._state_records.remove(name)

    def __setitem__(self, name, state_record):
        if name in self._name_to_state_records:
            raise Exception('State record of name "%s" already exists.' % name)

        self._name_to_state_records[name] = state_record
        self._state_records.append(state_record)

    def values(self):
        return self._state_records

    def keys(self):
        return self._name_to_state_records.iterkeys()

    def items(self):
        return self._name_to_state_records.iteritems()
