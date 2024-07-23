from __future__ import annotations


class IndirectJump:
    """
    A meta class describing an indirect jump instruction.
    """

    def __init__(self, mnemonic, resolved, targets=None) -> None:
        self.mnemonic = mnemonic
        self.resolved = resolved
        self.targets = targets
