"""
Test cases for XRefDialog.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from common import ProjectOpenTestCase

from angrmanagement.ui.dialogs.xref import XRefDialog


class TestXRefDialog(ProjectOpenTestCase):
    """Test XRefDialog functionality."""

    def test_xref_dialog_with_xrefs_manager(self):
        """Test XRefDialog creation with xrefs_manager (address-based xrefs)."""
        dialog = XRefDialog(
            addr=0x1000,
            dst_addr=0x2000,
            xrefs_manager=self.instance.project.kb.xrefs,
            instance=self.instance,
            parent=self.main,
        )

        assert dialog is not None
        assert isinstance(dialog, XRefDialog)
        dialog.close()

    def test_xref_dialog_with_variable_manager(self):
        """Test XRefDialog creation with variable_manager (variable-based xrefs)."""
        mock_variable = MagicMock()
        mock_variable_manager = MagicMock()

        dialog = XRefDialog(
            addr=0x1000,
            variable=mock_variable,
            variable_manager=mock_variable_manager,
            instance=self.instance,
            parent=self.main,
        )

        assert dialog is not None
        assert isinstance(dialog, XRefDialog)
        dialog.close()


if __name__ == "__main__":
    unittest.main()
