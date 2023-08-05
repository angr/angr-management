import itertools
from typing import Optional

from .block_objects import FunctionHeader, Label, PhiVariable, Variables


def locate_function(inst, addr):
    """
    Locate the function that contains the address.

    :param inst:
    :param int addr: The address.
    :return: The function object or None if address is not inside any function.
    :rtype: angr.knowledge_plugins.Function or None
    """

    if inst.cfg is None:
        return None

    functions = inst.kb.functions
    for _, function in functions.items():
        for block in function.blocks:
            if block.addr <= addr < block.addr + block.size:
                return function

    return None


def get_label_text(addr, kb, function=None):
    if addr in kb.labels:
        return kb.labels[addr] + ":"

    # default case
    if function is not None and addr == function.addr:
        s = []
        if function.name:
            s.append("%s:" % function.name)
        else:
            s.append("sub_%x:" % function.addr)
        if function.is_simprocedure:
            s.append("[SimProcedure]")
        if function.is_plt:
            s.append("[PLT]")
        return "\n".join(s)
    else:
        return "loc_%#x:" % addr


def get_block_objects(disasm, nodes, func_addr):
    """
    Get a list of objects to be displayed in a block in disassembly view. Objects may include instructions, stack
    variables, and labels.

    :param angr.analyses.Disassembly disasm:    The angr Disassembly Analysis instance.
    :param iterable nodes:                      A collection of CFG nodes.
    :param int func_addr:                       The function address of the current block.
    :return:                                    a list of Instruction objects and label names (strings).
    :rtype:                                     list
    """

    block_addrs = [node.addr for node in nodes]
    block_addr = block_addrs[0]
    insn_addrs = list(itertools.chain.from_iterable(disasm.block_to_insn_addrs[addr] for addr in block_addrs))

    lst = []

    variable_manager = disasm.kb.variables[func_addr]

    # function beginning
    if block_addr == func_addr:
        # function header
        try:
            func = disasm.kb.functions.get_by_addr(func_addr)
        except KeyError:
            func = None
        if func is not None and func.calling_convention is not None and func.prototype is not None:
            args = func.calling_convention.arg_locs(func.prototype)
            func_header = FunctionHeader(func.demangled_name, func.prototype, args)
            lst.append(func_header)

        # stack variables
        # filter out all stack variables
        variables = variable_manager.get_unified_variables(sort="stack")
        variables = sorted(variables, key=lambda v: v.offset)
        lst.append(Variables(variables))

    # phi variables
    phi_variables = variable_manager.get_phi_variables(block_addr)
    if phi_variables:
        for phi, variables in phi_variables.items():
            lst.append(PhiVariable(phi, variables))

    # instructions and labels
    for insn_addr in insn_addrs:
        if insn_addr != func_addr and insn_addr in disasm.kb.labels:
            lst.append(Label(insn_addr, get_label_text(insn_addr, disasm.kb)))
        lst.append(disasm.raw_result_map["instructions"][insn_addr])
        lst.extend(disasm.raw_result_map["ir"][insn_addr])

    # initial label, if there is any
    # FIXME: all labels should be generated during CFG recovery, and this step should not be necessary.
    if lst and not isinstance(lst[0], (FunctionHeader, Label)):
        # the first element should be a label
        lst.insert(0, Label(block_addrs[0], get_label_text(block_addrs[0], disasm.kb)))

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

    if len(out_branch_map) > 1:
        # if there are more than one targets, we return the union of non-default out branches
        keys = list(out_branch_map.keys())
        out_branch = None
        for k in keys:
            out_branch = out_branch_map[k].copy() if out_branch is None else out_branch.merge(out_branch_map[k])

        return out_branch

    else:
        return next(iter(out_branch_map.values()))


def fast_memory_load_pointer(project, addr, size=None):
    try:
        return project.loader.memory.unpack_word(addr, size=size)
    except KeyError:
        return None


def string_at_addr(cfg, addr, project, max_size=50):
    try:
        mem_data = cfg.memory_data[addr]
    except KeyError:
        return None

    if mem_data.sort == "string":
        str_content = mem_data.content.decode("utf-8")
    elif mem_data.sort == "pointer-array":
        ptr = fast_memory_load_pointer(project, mem_data.address)
        try:
            next_level = cfg.memory_data[ptr]
        except KeyError:
            return None

        if next_level.sort != "string":
            return None

        str_content = next_level.content.decode("utf-8")
    else:
        return None

    if str_content is not None:
        if len(str_content) > max_size:
            return '"' + filter_string_for_display(str_content[:max_size]) + '..."'
        else:
            return '"' + filter_string_for_display(str_content) + '"'
    else:
        return None


def should_display_string_label(cfg, insn_addr, project):
    if insn_addr not in cfg.insn_addr_to_memory_data:
        return False

    memory_data = cfg.insn_addr_to_memory_data[insn_addr]
    if memory_data.sort == "string":
        return True
    elif memory_data.sort == "pointer-array" and memory_data.size == cfg.project.arch.bytes:
        # load the pointer
        ptr = fast_memory_load_pointer(project, memory_data.address)
        try:
            # see if the pointer is pointing to a string
            return cfg.memory_data[ptr].sort == "string"
        except KeyError:
            return False

    return False


def is_printable(ch):
    return 32 <= ch < 127


def filter_string_for_display(s):
    output = ""
    for ch in s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t"):
        char = ord(ch)
        if not is_printable(char):
            ch = "\\x%0.2x" % char
        output += ch
    return output


def get_string_for_display(cfg, insn_addr, project, max_size=20) -> Optional[str]:
    str_content = None

    try:
        memory_data = cfg.insn_addr_to_memory_data[insn_addr]
    except KeyError:
        return None

    if memory_data.sort == "string":
        str_content = memory_data.content.decode("utf-8")
    elif memory_data.sort == "pointer-array":
        ptr = fast_memory_load_pointer(project, memory_data.address)
        if ptr in cfg.memory_data:
            next_level = cfg.memory_data[ptr]
            if next_level.sort == "string":
                str_content = next_level.content.decode("utf-8")

    if str_content is not None:
        if len(str_content) > max_size:
            return '"' + filter_string_for_display(str_content[:max_size]) + '..."'
        else:
            return '"' + filter_string_for_display(str_content) + '"'
    else:
        return None


def get_comment_for_display(kb, insn_addr):
    if insn_addr in kb.comments:
        return kb.comments[insn_addr]
    else:
        return None
