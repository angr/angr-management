from typing import List, Optional


class ComponentFunction:
    __slots__ = (
        "mapped_base",
        "virtual_addr",
        "symbol_name",
    )

    def __init__(self, mapped_base: int, virtual_addr: int, symbol_name: Optional[str] = None):
        self.mapped_base = mapped_base
        self.virtual_addr = virtual_addr
        self.symbol_name = symbol_name

    def __eq__(self, other):
        return (
            isinstance(other, ComponentFunction)
            and self.mapped_base == other.mapped_base
            and self.virtual_addr == other.virtual_addr
        )

    def __hash__(self):
        return hash((ComponentFunction, self.mapped_base, self.virtual_addr))


class ComponentTreeNode:
    def __init__(self, name=None):
        self.name = name
        self.components: List["ComponentTreeNode"] = []
        self.functions: List[ComponentFunction] = []

    def __eq__(self, other):
        return (
            isinstance(other, ComponentTreeNode)
            and self.components == other.components
            and set(self.functions) == set(other.functions)
        )

    def __hash__(self):
        return hash(
            (
                ComponentTreeNode,
                hash(tuple(self.components)),
                hash(tuple(sorted((f.mapped_base + f.virtual_addr) for f in self.functions))),
            )
        )


class ComponentTree:
    def __init__(self, root: Optional[ComponentTreeNode] = None):
        self.root = root
