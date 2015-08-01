_DUMMY = object()

def notify_update(o, attr):
    change = {
        'value': getattr(o, attr),
        'object': o,
        'type': 'update',
        'name': attr,
        'oldvalue': _DUMMY,
    }
    o.notify(attr, change)
    o.get_member(attr).notify(o, change)
