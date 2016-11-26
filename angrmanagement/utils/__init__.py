
def locate_function(inst, addr):
    """
    Locate the function that contains the address.

    :param inst:
    :param int addr: The address.
    :return: The function object or None if address is not inside any function.
    :rtype: angr.knowledge.Function or None
    """

    if inst.cfg is None:
        return None

    functions = inst.cfg.functions
    for _, function in functions.iteritems():
        for block in function.blocks:
            if block.addr <= addr < block.addr + block.size:
                return function

    return None

def get_block_header(addr, kb, function=None):

    if addr in kb.labels:
        return kb.labels[addr] + ":"

    # default case
    if function is not None and addr == function.addr:
        s = [ ]
        if function.name:
            s.append("%s:" % function.name)
        else:
            s.append("sub_%x:" % function.addr)
        if function.is_simprocedure:
            s.append('[SimProcedure]')
        if function.is_plt:
            s.append('[PLT]')
        return "\n".join(s)
    else:
        return "loc_%#x:" % addr
