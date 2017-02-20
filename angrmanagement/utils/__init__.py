
import itertools


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


def get_label_text(addr, kb, function=None):

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


def get_block_objects(disasm, nodes):
    """
    Get a list of instructions and labels to be displayed in a block in disassembly view.

    :param angr.analyses.Disassembly disasm: The angr Disassembly Analysis instance.
    :param iterable nodes: A collection of CFG nodes.
    :return: a list of Instruction objects and label names (strings).
    :rtype: list
    """

    block_addrs = [node.addr for node in nodes]
    insn_addrs = list(itertools.chain.from_iterable(disasm.block_to_insn_addrs[addr] for addr in block_addrs))

    lst = [ ]
    for insn_addr in insn_addrs:
        if insn_addr in disasm.kb.labels:
            lst.append((insn_addr, disasm.kb.labels[insn_addr] + ":"))
        lst.append(disasm.raw_result_map['instructions'][insn_addr])

    if lst and not isinstance(lst[0], tuple):
        # the first element should be a label
        lst.insert(0, (block_addrs[0], get_label_text(block_addrs[0], disasm.kb)))

    return lst


def get_out_branches(supernode):
    """
    Get a list of descriptors of branches going out from the supernode.

    :param SuperCFGNode supernode: The node to work with.
    :return: A list of out branch descriptors.
    :rtype: list
    """

    return supernode.out_branches


def address_to_text(addr, kb):
    """
    Properly convert an address to text for a label.

    :param int addr: The address to convert.
    :param angr.KnowledgeBase kb: The knowledgebase in use.
    :return: Text representation of the address.
    :rtype: str
    """

    if addr in kb.labels:
        return kb.labels[addr]

    return "loc_%#x" % addr

def get_out_branches_for_insn(out_branch_dict, ins_addr):

    if ins_addr not in out_branch_dict:
        return None

    out_branch_map = out_branch_dict[ins_addr]

    if len(out_branch_map) > 1 and 'default' in out_branch_map:
        # if there are more than one targets, we return the union of non-default out branches
        keys = out_branch_map.keys()
        out_branch = None
        for k in keys:
            if k == 'default':
                continue
            out_branch = out_branch_map[k].copy() if out_branch is None else out_branch.merge(out_branch_map[k])

        return out_branch

    else:
        return next(out_branch_map.itervalues())


def should_display_string_label(cfg, insn_addr):
    memory_data = cfg.insn_addr_to_memory_data[insn_addr]
    if memory_data.sort == 'string':
        return True
    elif memory_data.sort == 'pointer-array' and memory_data.size == cfg.project.arch.bits / 8:
        # load the pointer
        ptr = cfg._fast_memory_load_pointer(memory_data.address)
        try:
            # see if the pointer is pointing to a string
            return cfg.memory_data[ptr].sort == 'string'
        except KeyError:
            return False

    return False


def get_string_for_display(cfg, memory_data):

    MAX_SIZE = 20

    str_content = None

    if memory_data.sort == "string":
        str_content = memory_data.content
    elif memory_data.sort == 'pointer-array':
        ptr = cfg._fast_memory_load_pointer(memory_data.address)
        if ptr in cfg.memory_data:
            next_level = cfg.memory_data[ptr]
            if next_level.sort == 'string':
                str_content = next_level.content

    if str_content is not None:
        if len(str_content) > MAX_SIZE: return '"' + str_content[:MAX_SIZE] + '..."'
        else: return '"' + str_content + '"'
    else:
        return '<Unknown>'
