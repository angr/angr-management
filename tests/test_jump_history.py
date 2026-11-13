from __future__ import annotations

import unittest

from angrmanagement.logic.disassembly.jump_history import JumpHistory


class TestJumpHistory(unittest.TestCase):
    def test_empty_navigation(self):
        history = JumpHistory()
        self.assertIsNone(history.current)
        self.assertIsNone(history.backtrack())
        self.assertIsNone(history.forwardstep())
        self.assertIsNone(history.forwardstep())
        self.assertEqual(history.pos, -1)

    def test_forward_and_backward_boundaries(self):
        history = JumpHistory()
        history.jump_to(0x10)
        history.jump_to(0x20)
        self.assertEqual(history.backtrack(), 0x10)
        self.assertEqual(history.backtrack(), 0x10)
        self.assertEqual(history.forwardstep(), 0x20)
        self.assertEqual(history.forwardstep(), 0x20)

    def test_new_jump_trims_forward_history(self):
        history = JumpHistory()
        history.jump_to(0x10)
        history.jump_to(0x20)
        history.backtrack()
        history.jump_to(0x30)
        self.assertEqual(history.history, [0x10, 0x30])
        self.assertEqual(history.forwardstep(), 0x30)


if __name__ == "__main__":
    unittest.main()
