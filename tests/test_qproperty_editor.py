# pylint:disable=missing-class-docstring
from __future__ import annotations

import unittest

from common import AngrManagementTestCase
from PySide6.QtCore import QModelIndex, Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QComboBox

from angrmanagement.ui.widgets.qproperty_editor import (
    BoolPropertyItem,
    ColorPropertyItem,
    ComboPropertyItem,
    FilePropertyItem,
    FloatPropertyItem,
    FontPropertyItem,
    GroupPropertyItem,
    IntPropertyItem,
    PropertyModel,
    QPropertyEditor,
    TextPropertyItem,
    for_all_model_rows,
)

SLOW_TEST = False


def w():
    if SLOW_TEST:
        QTest.qWait(1000)


class TestQPropertyEditor(AngrManagementTestCase):
    def setUp(self):
        super().setUp()
        self.root = GroupPropertyItem(
            "Root",
            description="Root of all properties.",
            children=[
                GroupPropertyItem(
                    "General",
                    description="General settings for the object.",
                    children=[
                        TextPropertyItem("Name", "Sample Object", description="The name of the object."),
                        BoolPropertyItem(
                            "Enabled",
                            True,
                            description="Enable or disable the object.",
                            children=[
                                TextPropertyItem("Subprop1", "Sub-property 1", description="I'm a sub-property"),
                                TextPropertyItem(
                                    "Subprop2",
                                    "Sub-property 2",
                                    description="I'm a sub-property",
                                    children=[
                                        TextPropertyItem(
                                            "Subsubprop", "Sub-sub-property", description="I'm a sub-sub-property"
                                        ),
                                    ],
                                ),
                            ],
                        ),
                        FontPropertyItem("Font", QFont("Arial", 10), description="Select a font."),
                        FilePropertyItem("File", "", description="Select a file."),
                    ],
                ),
                GroupPropertyItem(
                    "Size",
                    description="Size settings.",
                    children=[
                        IntPropertyItem("Width", 100, minimum=0, maximum=1000, description="The width in pixels."),
                        IntPropertyItem("Height", 200, minimum=0, maximum=1000, description="The height in pixels."),
                    ],
                ),
                GroupPropertyItem(
                    "Appearance",
                    description="Visual appearance settings.",
                    children=[
                        FloatPropertyItem(
                            "Opacity",
                            0.85,
                            minimum=0.0,
                            maximum=1.0,
                            decimals=2,
                            description="The opacity (transparency level).",
                        ),
                        ColorPropertyItem("Background Color", QColor("blue"), description="The background color."),
                        ComboPropertyItem(
                            "Style", "Solid", ["Solid", "Dashed", "Dotted"], description="The border style."
                        ),
                    ],
                ),
            ],
        )

        self.model = PropertyModel(self.root)
        self.tree_view = QPropertyEditor()
        self.tree_view.setModel(self.model)
        self.tree_view.setWindowTitle("Property Editor")
        self.tree_view.resize(500, 500)
        self.tree_view.show()

        self.tv = self.tree_view._tree_view
        self.tv.setFocus()

        w()

    def tearDown(self):
        super().tearDown()
        self.tree_view.hide()
        del self.tree_view

    def test_desc_box_updates(self):
        general_prop = self.root.children[0]
        self._click_on_prop(general_prop)
        assert general_prop.name in self.tree_view._desc_box.toPlainText()
        w()

        name_prop = self.root.children[0].children[0]
        self._click_on_prop(name_prop)
        assert name_prop.description in self.tree_view._desc_box.toPlainText()
        w()

    def test_text_prop(self):
        prop = self.root.children[0].children[0]
        assert isinstance(prop, TextPropertyItem)

        # Double click to edit
        self._click_on_prop(prop, double=True)
        w()

        # Update text
        new_text = "New Value"
        QTest.keyClicks(self.tv.focusWidget(), new_text)
        QTest.keyClick(self.tv.focusWidget(), Qt.Key.Key_Return)
        QApplication.processEvents()
        w()

        self.assertEqual(prop.value, new_text)

    def test_bool_prop(self):
        prop = self.root.children[0].children[1]
        assert isinstance(prop, BoolPropertyItem)

        initial_value = prop.value

        # Click on it
        self._click_on_prop(prop)
        QApplication.processEvents()
        assert prop.value == (not initial_value)
        w()

        # Click again
        self._click_on_prop(prop)
        QApplication.processEvents()
        assert prop.value == initial_value
        w()

    def test_combo_prop(self):
        prop = self.root.children[2].children[2]
        assert isinstance(prop, ComboPropertyItem)

        initial_value = prop.value

        # Double click to edit
        self._click_on_prop(prop, double=True)
        w()

        # Select next item
        combo = self.tv.focusWidget()
        assert isinstance(combo, QComboBox)

        combo.setCurrentIndex(combo.currentIndex() + 1)
        new_data = combo.currentData()
        assert new_data != initial_value
        w()

        # Accept
        QTest.keyClick(combo, Qt.Key.Key_Return)
        QApplication.processEvents()
        assert prop.value == new_data
        w()

    def test_expand_prop_with_double_click(self):
        for prop in self._iter_props(self.root):
            if not prop.children:
                continue

            idx = self._prop_to_index(prop)

            # Collapse
            self._click_on_prop(prop, col=0, double=True)
            assert not self.tv.isExpanded(idx)
            w()

            # Expand
            self._click_on_prop(prop, col=0, double=True)
            assert self.tv.isExpanded(idx)
            w()

    def test_expand_prop_with_arrow(self):
        for prop in self._iter_props(self.root):
            if not prop.children:
                continue

            idx = self._prop_to_index(prop)

            # Get branch arrow widget location
            vr = self.tv.visualRect(idx)
            pos = vr.center()
            pos.setX(int(vr.height() / 2))

            # Collapse
            QTest.mouseClick(self.tv.viewport(), Qt.MouseButton.LeftButton, pos=pos)
            assert not self.tv.isExpanded(idx)
            w()

            # Expand
            QTest.mouseClick(self.tv.viewport(), Qt.MouseButton.LeftButton, pos=pos)
            assert self.tv.isExpanded(idx)
            w()

    def test_filter(self):
        text = "subprop1"
        prop = self.root.children[0].children[1].children[0]

        # Gather expected (all parents but root)
        expected_visible = {prop}
        while prop.parent and prop.parent.parent:
            expected_visible.add(prop.parent)
            prop = prop.parent

        # Gather initially visible
        initially_visible = self._get_visible_props()

        # Set filter text
        self.tree_view._filter_box.setText(text)
        w()

        # Check visible items
        assert expected_visible == self._get_visible_props()
        w()

        # Clear filter
        self.tree_view._filter_box.setText("")
        assert initially_visible == self._get_visible_props()
        w()

    # FIXME: Test Color
    # FIXME: Test Int
    # FIXME: Test Float
    # FIXME: Test File
    # FIXME: Test Font

    def _iter_props(self, item):
        if item is not self.root:
            yield item
        for c in item.children:
            yield from self._iter_props(c)

    def _prop_to_index(self, prop, col=0) -> QModelIndex:
        indices = []
        for_all_model_rows(self.tree_view._proxy_model, indices.append)
        for index in indices:
            if not index.isValid():
                continue
            prop_at_index = self.tree_view._proxy_model.mapToSource(index).internalPointer()
            if prop_at_index is prop:
                if col:
                    return index.siblingAtColumn(col)
                return index
        raise KeyError("Could not resolve index")

    def _click_on_prop(self, prop, col=1, double=False):
        QApplication.processEvents()
        index = self._prop_to_index(prop, col)
        pos = self.tv.visualRect(index).center()
        vp = self.tv.viewport()

        QApplication.processEvents()

        if double:
            # Bug in QTreeView::mouseDoubleClickEvent? Events are being sent in but the double click doesn't trigger
            QTest.mouseClick(vp, Qt.MouseButton.LeftButton, pos=pos)
            QTest.qWait(250)

            QTest.mouseDClick(vp, Qt.MouseButton.LeftButton, pos=pos)
        else:
            QTest.mouseClick(vp, Qt.MouseButton.LeftButton, pos=pos)

        QApplication.processEvents()

    def _get_visible_props(self):
        visible = set()

        def on_index(index):
            if index.isValid():
                visible.add(self.tree_view._proxy_model.mapToSource(index).internalPointer())

        for_all_model_rows(self.tree_view._proxy_model, on_index)
        return visible


if __name__ == "__main__":
    unittest.main()
