
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