from __future__ import annotations


class JumpHistory:
    """
    A class to store the navigation history of a reversing session. Typically found at DisassemblyView._jump_history
    or CodeView.jump_history. Maintains a list of addresses through which the user can navigate forwards and backwards.
    """

    def __init__(self) -> None:
        self._history = []
        self._pos = -1

    @property
    def history(self):
        return self._history

    @property
    def pos(self):
        return self._pos

    @property
    def current(self):
        if len(self._history):
            return self._history[self._pos]
        else:
            return None

    def __len__(self) -> int:
        return len(self._history)

    def jump_to(self, addr: int) -> None:
        if self._pos != len(self._history) - 1:
            self.trim()

        if not self._history or self._history[-1] != addr:
            self._history.append(addr)
            self._pos = len(self._history) - 1

    def record_address(self, addr: int) -> None:
        if 0 <= self._pos < len(self._history):
            self._history[self._pos] = addr
        else:
            self.jump_to(addr)

    def trim(self) -> None:
        self._history = self._history[: self._pos + 1]

    def backtrack(self):
        if self._pos > 0:
            self._pos -= 1

        if not 0 <= self._pos < len(self._history):
            return None
        else:
            return self._history[self._pos]

    def forwardstep(self):
        if self._pos < len(self._history) - 1:
            self._pos += 1

        if self._pos < len(self._history):
            return self._history[self._pos]
        else:
            return None

    def step_position(self, pos: int):
        if -1 < pos < len(self._history):
            self._pos = pos
        return self._history[self._pos]
