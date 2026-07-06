"""
Test cases for the Overview entry in AnalysisOptionsDialog.
"""

# pylint: disable=no-self-use,protected-access

from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock, patch

import angr
from common import create_qapp, test_location  # pylint: disable=import-error
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox

from angrmanagement.data.analysis_options import AnalysesConfiguration
from angrmanagement.data.instance import Instance
from angrmanagement.data.jobs import (
    OverviewConfiguration,
    RustSymbolRecoveryConfiguration,
    RustTypeDBLoaderConfiguration,
)
from angrmanagement.data.jobs.overview import SUPPORTED_LANGUAGES, _detect_default_language
from angrmanagement.ui.dialogs.analysis_options import RUST_DEPENDENT_ANALYSES, AnalysisOptionsDialog


def _make_instance_with_project() -> Instance:
    inst = Instance()
    inst.project.am_obj = angr.Project(os.path.join(test_location, "x86_64", "true"))
    return inst


class TestOverviewConfiguration(unittest.TestCase):
    """Test OverviewConfiguration construction and defaults."""

    @classmethod
    def setUpClass(cls):
        create_qapp()

    def setUp(self):
        self._instance = _make_instance_with_project()

    def test_default_matches_project_detection(self):
        detected = self._instance.project.am_obj.languages()[0]
        # The detector returns a supported language for our test binary
        assert detected in SUPPORTED_LANGUAGES
        ov = OverviewConfiguration(self._instance)
        assert ov.name == "overview"
        assert ov.display_name == "Overview"
        assert ov.enabled is True
        assert "languages" in ov.options
        assert ov.options["languages"].value == detected
        assert ov.options["languages"].default == detected

    def test_default_falls_back_when_detection_unsupported(self):
        self._instance.project.am_obj._languages = ["fortran"]
        ov = OverviewConfiguration(self._instance)
        assert ov.options["languages"].value == "unknown"

    def test_choices_match_supported_languages(self):
        ov = OverviewConfiguration(self._instance)
        assert ov.options["languages"].choices == SUPPORTED_LANGUAGES
        assert set(SUPPORTED_LANGUAGES) == {"c", "go", "rust", "swift", "unknown"}

    def test_detect_default_falls_back_to_unknown_when_no_project(self):
        no_project = Instance()
        assert _detect_default_language(no_project) == "unknown"

    def test_detect_default_falls_back_to_unknown_for_unsupported_language(self):
        self._instance.project.am_obj._languages = ["fortran"]
        assert _detect_default_language(self._instance) == "unknown"


class TestAnalysisOptionsDialogOverview(unittest.TestCase):
    """Test the Overview entry's interactions in AnalysisOptionsDialog."""

    @classmethod
    def setUpClass(cls):
        create_qapp()

    def setUp(self):
        self._instance = _make_instance_with_project()
        self.project._languages = None
        self.workspace = MagicMock()

    @property
    def project(self):
        return self._instance.project.am_obj

    def _build_configs(self) -> AnalysesConfiguration:
        return AnalysesConfiguration(
            [
                OverviewConfiguration(self._instance),
                RustSymbolRecoveryConfiguration(self._instance),
                RustTypeDBLoaderConfiguration(self._instance),
            ]
        )

    def _build_dialog(self, configs):
        return AnalysisOptionsDialog(configs, self.workspace)

    def test_overview_item_present_in_list(self):
        configs = self._build_configs()
        dlg = self._build_dialog(configs)
        try:
            labels = [dlg._analysis_list.item(i).text() for i in range(dlg._analysis_list.count())]
            assert "Overview" in labels
            assert "overview" in dlg._items_by_name
        finally:
            dlg.close()

    def test_rust_prompt_enables_rust_analyses_on_yes(self):
        configs = self._build_configs()
        assert configs.by_name("rust_symbol_recovery").enabled is False
        assert configs.by_name("rust_typedb_loader").enabled is False

        dlg = self._build_dialog(configs)
        try:
            with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes) as q:
                dlg._on_language_changed("rust")
                assert q.call_count == 1

            for name in RUST_DEPENDENT_ANALYSES:
                cfg = configs.by_name(name)
                assert cfg.enabled is True
                assert dlg._items_by_name[name].checkState() == Qt.CheckState.Checked
        finally:
            dlg.close()

    def test_rust_prompt_does_nothing_on_no(self):
        configs = self._build_configs()
        dlg = self._build_dialog(configs)
        try:
            with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.No):
                dlg._on_language_changed("rust")
            for name in RUST_DEPENDENT_ANALYSES:
                assert configs.by_name(name).enabled is False
                assert dlg._items_by_name[name].checkState() == Qt.CheckState.Unchecked
        finally:
            dlg.close()

    def test_non_rust_disables_rust_analyses_with_confirmation(self):
        configs = self._build_configs()
        configs.by_name("rust_symbol_recovery").enabled = True
        configs.by_name("rust_typedb_loader").enabled = True

        dlg = self._build_dialog(configs)
        for name in RUST_DEPENDENT_ANALYSES:
            dlg._items_by_name[name].setCheckState(Qt.CheckState.Checked)
        try:
            with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
                dlg._on_language_changed("go")
            for name in RUST_DEPENDENT_ANALYSES:
                assert configs.by_name(name).enabled is False
                assert dlg._items_by_name[name].checkState() == Qt.CheckState.Unchecked
        finally:
            dlg.close()

    def test_no_prompt_when_state_already_matches(self):
        configs = self._build_configs()
        dlg = self._build_dialog(configs)
        try:
            with patch.object(QMessageBox, "question") as q:
                dlg._on_language_changed("c")
                q.assert_not_called()
        finally:
            dlg.close()

    def test_language_change_syncs_to_project(self):
        configs = self._build_configs()
        dlg = self._build_dialog(configs)
        try:
            with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
                dlg._on_language_changed("rust")
            assert self.project._languages == ["rust"]
            assert self.project.languages() == ["rust"]
            assert self.project.is_rust_binary is True

            with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
                dlg._on_language_changed("go")
            assert self.project._languages == ["go"]
            assert self.project.is_rust_binary is False
        finally:
            dlg.close()


if __name__ == "__main__":
    unittest.main()
