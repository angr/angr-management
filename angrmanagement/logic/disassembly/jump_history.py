

class JumpHistory(object):
    def __init__(self):
        self._history = [ ]
        self._pos = -1

    def __len__(self):
        return len(self._history)

    def jump_to(self, addr):

        if self._pos != len(self._history) - 1:
            self.trim()

        if not self._history or self._history[-1] != addr:
            self._history.append(addr)
            self._pos = len(self._history) - 1

    # TODO this should maybe not adjust pos and just update the most recent entry
    def record_address(self, addr):

        if self._pos != len(self._history) - 1:
            self.trim()

        if not self._history or self._history[-1] != addr:
            self._history.append(addr)
            self._pos = len(self._history) - 1

    def trim(self):
        self._history = self._history[ : self._pos + 1]

    def backtrack(self):
        if self._pos > -1:
            self._pos -= 1

        if not (0 <= self._pos < len(self._history)):
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
