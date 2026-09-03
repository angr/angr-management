# Testing Guide for angr-management

This guide describes best practices for writing tests in angr-management, based on established patterns in the test suite.

## Quick Start: Verify Your Tests Meet Standards

After writing tests, run these commands to verify they meet our quality standards:

```bash
# 1. Activate virtual environment
source ~/.virtualenvs/angr/bin/activate

# 2. Run tests (should all pass)
pytest tests/test_my_view.py -v

# 3. Check pylint (should be 10.00/10)
pylint --rcfile=/home/matt/work/angr/angr-dev/pylintrc tests/test_my_view.py

# 4. Check ruff (should pass with 0 errors)
ruff check tests/test_my_view.py

# 5. Check pyright (should have 0 errors, 0 warnings)
pyright tests/test_my_view.py
```

**All checks must pass before submitting tests.**

---

## Table of Contents
- [Quick Start](#quick-start-verify-your-tests-meet-standards)
- [Testing Philosophy](#testing-philosophy)
- [Test Structure](#test-structure)
- [Test Class Organization](#test-class-organization)
- [Dialog Testing](#dialog-testing)
- [Qt-Specific Testing](#qt-specific-testing)
- [Mock Usage](#mock-usage)
- [Type Safety](#type-safety)
- [Code Quality](#code-quality)
- [Coverage Goals](#coverage-goals)
- [Common Pitfalls](#common-pitfalls)
- [Running Tests](#running-tests)
- [Debugging Failing Tests](#debugging-failing-tests)
- [Commit Messages](#commit-messages)

---

## Table of Contents (Detailed)
- [Testing Philosophy](#testing-philosophy)
- [Test Structure](#test-structure)
- [Test Class Organization](#test-class-organization)
- [Dialog Testing](#dialog-testing)
- [Qt-Specific Testing](#qt-specific-testing)
- [Mock Usage](#mock-usage)
- [Type Safety](#type-safety)
- [Code Quality](#code-quality)
- [Coverage Goals](#coverage-goals)
- [Common Pitfalls](#common-pitfalls)
- [Debugging Failing Tests](#debugging-failing-tests)
- [Commit Messages](#commit-messages)

---

## Testing Philosophy

### Prefer Unit Tests, Use Integration Tests Sparingly

**Goal:** Write small, focused tests that test one piece of functionality in isolation. Use integration tests only when necessary to verify end-to-end behavior.

### Three Types of Tests

#### 1. Unit Tests (Preferred for Most Cases)

Test one component in isolation with mocked dependencies:

```python
# Unit test: Test business logic without UI
def test_g_key_calls_popup_jumpto(self):
    """Test that 'g' key routes to popup_jumpto_dialog."""
    with patch.object(self.view, "popup_jumpto_dialog") as mock_popup:
        key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_G, Qt.KeyboardModifier.NoModifier)
        self.view.keyPressEvent(key_event)
        mock_popup.assert_called_once()
```

**Use for:** Business logic, routing, method interactions

#### 2. Component Tests (For UI Widgets)

Test actual UI component behavior without mocking:

```python
# Component test: Test widget behavior
def test_property_editor_updates_value(self):
    """Test that QPropertyEditor correctly updates when value changes."""
    editor = QPropertyEditor()
    editor.setValue(42)
    assert editor.getValue() == 42
```

**Use for:** Widget functionality (QPropertyEditor, custom controls, UI components)

**Example:** `test_qproperty_editor.py` tests actual widget behavior

#### 3. Integration Tests (Use Sparingly)

Test multiple layers working together end-to-end:

```python
# Integration test: Test full flow
def test_g_key_opens_jumpto_dialog_and_navigates(self):
    """Test that pressing 'g' opens dialog and navigates to address."""
    # Tests keyboard → dialog → navigation
    # Useful for critical paths, but slow and brittle
```

**Use for:** Critical end-to-end workflows that must work together

**Caution:** Integration tests are slow, brittle (break when any layer changes), and provide poor error messages. Use them sparingly for critical paths only.

### When to Mock vs When Not to Mock

**Mock dialogs when testing business logic:**
```python
# Testing routing logic - mock the dialog
def test_menu_action_opens_dialog(self):
    with patch.object(self.view, "popup_xref_dialog") as mock:
        self.view._menu._popup_xrefs()
        mock.assert_called_once()
```

**Don't mock when testing the UI component itself:**
```python
# Testing widget behavior - use actual widget
def test_property_editor_validates_input(self):
    editor = QPropertyEditor()
    editor.setValue("invalid")
    assert editor.hasError()
```

### Benefits of Focusing on Unit Tests

- **Precise failure identification** - Know exactly what broke
- **Fast execution** - Mocked dependencies, no I/O
- **Independent** - Tests don't affect each other
- **Easy to maintain** - Small, focused, clear purpose
- **Better coverage** - Test edge cases without complex setup

---

## Test Structure

### File Organization

Tests should be organized by the component they test:
- `test_disassembly_view.py` → Tests for `DisassemblyView`
- `test_hex_view.py` → Tests for `HexView`
- `test_code_view.py` → Tests for `CodeView`

### Base Test Classes

Choose the appropriate base class based on what your component needs:

#### 1. `unittest.TestCase` - Pure Python Components

For testing pure Python logic that doesn't need Qt or angr:

```python
import unittest

class TestMyUtility(unittest.TestCase):
    def test_parse_function(self):
        # Test pure Python functions
        pass
```

**Use when:** Testing utilities, parsers, data structures that don't interact with UI or angr.

#### 2. `AngrManagementTestCase` - UI Without Project

For testing UI components that don't require a loaded angr project:

```python
from common import AngrManagementTestCase

class TestQPropertyEditor(AngrManagementTestCase):
    def setUp(self):
        super().setUp()
        # self.main is available (MainWindow)
        # QApplication is running
        # NO project loaded
```

**Provides:**
- MainWindow instance (`self.main`)
- Running QApplication
- Qt event loop

**Use when:** Testing dialogs, widgets, property editors, preferences that work without a project.

**Examples:** `test_qproperty_editor.py`, standalone dialog tests

#### 3. `ProjectOpenTestCase` - Views Requiring Project

For testing components that need a loaded angr project:

```python
from common import ProjectOpenTestCase

class TestDisassemblyView(ProjectOpenTestCase):
    def setUp(self):
        super().setUp()
        # self.workspace - initialized workspace
        # self.instance - loaded project instance
        # self.project - angr.Project
```

**Provides:**
- Everything from `AngrManagementTestCase`
- Workspace (`self.workspace`)
- Instance with loaded project (`self.instance`)
- angr.Project (`self.project`)

**Use when:** Testing views (DisassemblyView, CodeView, HexView) or components that analyze binaries.

**Examples:** `test_disassembly_view.py`, `test_code_view.py`, `test_hex_view.py`

### Choosing the Right Base Class

```
unittest.TestCase
    ↓ (needs Qt/UI)
AngrManagementTestCase
    ↓ (needs angr project)
ProjectOpenTestCase
```

**Rule of thumb:** Use the simplest base class that provides what you need. Don't load a project if you don't need it - it's slower and adds unnecessary complexity.

**Performance comparison:**
- `unittest.TestCase`: Instant setup
- `AngrManagementTestCase`: ~2-3 seconds (Qt initialization)
- `ProjectOpenTestCase`: ~5-10 seconds (Qt + project loading)

Choose wisely to keep your test suite fast.

### Refactoring to Lighter Base Classes

Start with the heavier base class that works, then refactor to lighter ones:

```python
# Initial version - works but slow
class TestCommandPaletteModel(AngrManagementTestCase):
    def setUp(self):
        super().setUp()
        self.model = CommandPaletteModel(self.main.workspace)

    def test_model_filters_commands(self):
        self.main.workspace.command_manager.register_command(cmd)
        # Test uses full MainWindow setup
```

**Refactor to:** Create your own minimal dependencies

```python
# Refactored - faster and more focused
class TestCommandPaletteModel(unittest.TestCase):
    def setUp(self):
        # Create only what you need
        self.mock_workspace = MagicMock()
        self.command_manager = CommandManager()  # Use real lightweight object
        self.mock_workspace.command_manager = self.command_manager
        self.model = CommandPaletteModel(self.mock_workspace)

    def test_model_filters_commands(self):
        self.command_manager.register_command(cmd)
        # Test runs without Qt/MainWindow overhead
```

**Benefits:**
- **10x faster** - No Qt/MainWindow initialization
- **More isolated** - Each test creates its own dependencies
- **Clearer intent** - Obvious what the test actually needs

**When to refactor:**
- Test runs slower than 1 second
- Test doesn't use UI components (dialogs, widgets)
- Test doesn't need angr project
- You're only using `self.main.workspace.X` - create your own mock workspace

**Real-world example:** `test_command_palette.py`
- 26 of 60 tests (43%) use `unittest.TestCase`
- Execution time: 38s vs 42s (10% faster)
- Individual test classes run in <1s instead of ~5s

### Use Real Objects When They're Lightweight

Don't mock everything - use real objects when they're simple:

```python
# BAD - Over-mocking
class TestMyModel(unittest.TestCase):
    def setUp(self):
        self.mock_command_manager = MagicMock()
        self.mock_command_manager.get_commands.return_value = []
        # Now you need to mock register_command, etc.
```

```python
# GOOD - Use real lightweight object
from angrmanagement.logic.commands.command_manager import CommandManager

class TestMyModel(unittest.TestCase):
    def setUp(self):
        self.command_manager = CommandManager()  # Real object!
        # It just works, no mocking needed
```

**Prefer real objects for:**
- Simple data containers (`CommandManager`, `Command`, etc.)
- Pure Python classes without complex dependencies
- Objects that don't require Qt/UI/database/network

**Mock when:**
- Object requires complex setup (MainWindow, Workspace)
- Object has side effects (network calls, file I/O)
- Object is slow to initialize
- You're testing error conditions

### Use Dummy Classes for Type Parameters

When code only needs a class type for `isinstance()` checks (not actual functionality), use a lightweight dummy class instead of importing heavy dependencies:

```python
# BAD - Imports heavy UI class just for type checking
from angrmanagement.ui.views.disassembly_view import DisassemblyView

class TestViewCommand(unittest.TestCase):
    def test_view_command(self):
        cmd = ViewCommand("test", "Test", action, DisassemblyView, workspace)
        # DisassemblyView brings in Qt, UI dependencies, etc.
```

```python
# GOOD - Dummy class for type parameter
class DummyView:
    """Lightweight dummy view class for testing ViewCommand without UI dependencies."""
    pass

class TestViewCommand(unittest.TestCase):
    def test_view_command(self):
        # Use type: ignore if dummy class doesn't match type annotation
        cmd = ViewCommand("test", "Test", action, DummyView, workspace)  # type: ignore[arg-type]
```

**When to use dummy classes:**
- ✅ Code only uses the class for `isinstance()` checks
- ✅ You don't need any actual methods or attributes
- ✅ Real class has heavy dependencies (Qt, database, network)
- ✅ Test only verifies type-checking logic, not class functionality

**When NOT to use dummy classes:**
- ❌ Code calls methods on the class
- ❌ Code accesses class attributes
- ❌ Real class is lightweight (just use it directly)
- ❌ Testing actual class behavior (use real class or MagicMock with spec)

**Real-world example:** `test_command_palette.py` uses `DummyView` instead of `DisassemblyView`:
- ViewCommand only checks `isinstance(view, view_class)`
- DummyView is 3 lines vs importing entire UI stack
- Tests run faster with zero UI dependencies
- Use `# type: ignore[arg-type]` to suppress type warnings

---

## Test Class Organization

### Separate Concerns into Test Classes

Organize tests by functional area using inheritance:

```python
class TestViewBase(ProjectOpenTestCase):
    """Base class with shared setup for all view tests."""

    def setUp(self):
        super().setUp()
        self.view = MyView(self.workspace, "center", self.instance)

    def tearDown(self):
        if hasattr(self, "view"):
            self.view.close()
            del self.view
        super().tearDown()


class TestPopupDialogs(TestViewBase):
    """Test popup_*_dialog methods that create and show dialogs."""

    def setUp(self):
        super().setUp()
        # Dialog-specific setup
        self._setup_dialog_mocks()


class TestKeyboardShortcuts(TestViewBase):
    """Test keyboard shortcut routing in keyPressEvent."""

    def test_g_key_calls_popup_jumpto(self):
        # Test keyboard routing
        pass


class TestContextMenus(TestViewBase):
    """Test context menu creation and actions."""

    def test_menu_creation(self):
        # Test menu behavior
        pass
```

### Benefits of This Organization

1. **Clear Separation**: Each class has a single responsibility
2. **Shared Setup**: Base class handles common initialization
3. **Easy Navigation**: Developers can quickly find relevant tests
4. **Test Isolation**: Each test gets a fresh view instance

### Avoid Artificial Test Class Separation

Don't create separate test classes for "edge cases" - they're just tests and should be co-located with the component they test.

**Bad - Artificial Separation:**
```python
class TestPaletteDialog(AngrManagementTestCase):
    """Test PaletteDialog base functionality."""

    def test_dialog_initialization(self):
        pass

    def test_enter_key_accepts_dialog(self):
        pass


class TestPaletteDialogEdgeCases(AngrManagementTestCase):  # ❌ Artificial separation
    """Test PaletteDialog edge cases."""

    def test_get_selected_returns_none_when_nothing_selected(self):
        pass

    def test_other_keys_passed_to_parent(self):
        pass
```

**Good - Co-located Tests:**
```python
class TestPaletteDialog(AngrManagementTestCase):  # ✅ All tests together
    """Test PaletteDialog functionality."""

    def test_dialog_initialization(self):
        pass

    def test_enter_key_accepts_dialog(self):
        pass

    def test_get_selected_returns_none_when_nothing_selected(self):
        pass

    def test_other_keys_passed_to_parent(self):
        pass
```

**Why this matters:**
- Edge cases aren't a different "concern" - they test the same component
- Separating them adds overhead (duplicate setUp/tearDown)
- Makes it harder to see all tests for a component
- Creates artificial boundaries that don't reflect actual code organization

**When to create separate test classes:**
- Different components (`TestPaletteDialog` vs `TestCommandPaletteDialog`)
- Different concerns (`TestPopupDialogs` vs `TestKeyboardShortcuts`)
- Different base classes needed (`unittest.TestCase` vs `AngrManagementTestCase`)

**When NOT to create separate test classes:**
- "Edge cases" vs "normal cases" - just different tests for the same component
- "Success cases" vs "failure cases" - just different test scenarios
- "Simple tests" vs "complex tests" - complexity doesn't define organization

---

## Dialog Testing

### Pattern: Mock Dialog Methods for Business Logic Tests

When testing business logic that triggers dialogs, mock `show()` and `exec_()` to avoid displaying actual UI:

```python
class TestPopupDialogs(TestViewBase):
    def setUp(self):
        super().setUp()

        self._show_called = False
        self._exec_called = False
        self._dialog_instance = None

        def mock_show(dialog_self):
            self._show_called = True
            self._dialog_instance = dialog_self
            QApplication.processEvents()

        def mock_exec(dialog_self, *_args, **_kwargs):
            self._exec_called = True
            self._dialog_instance = dialog_self
            QApplication.processEvents()
            return QDialog.DialogCode.Accepted

        self._show_patcher = patch("PySide6.QtWidgets.QDialog.show", mock_show)
        self._exec_patcher = patch("PySide6.QtWidgets.QDialog.exec_", mock_exec)
        self._show_patcher.start()
        self._exec_patcher.start()
        self.addCleanup(self._show_patcher.stop)
        self.addCleanup(self._exec_patcher.stop)
```

### Test Dialog Creation

```python
def test_popup_jumpto_dialog(self):
    """Test that popup_jumpto_dialog creates and shows JumpTo dialog (non-modal)."""
    self.view.popup_jumpto_dialog()

    assert self._show_called, "JumpTo dialog should be shown with .show()"
    assert isinstance(self._dialog_instance, JumpTo)
    self._dialog_instance.close()
```

### Modal vs Non-Modal Dialogs

- **Non-modal** dialogs use `.show()` → User can interact with other windows
- **Modal** dialogs use `.exec_()` → Blocks until dialog is closed

Document this distinction in test docstrings.

### When NOT to Mock Dialogs

Don't mock dialogs when you're testing the dialog itself or UI component behavior:

```python
# Testing the dialog component itself - no mocking
class TestJumpToDialog(AngrManagementTestCase):
    def test_dialog_validates_address(self):
        """Test that JumpTo dialog validates address input."""
        dialog = JumpTo(workspace=self.main.workspace)
        dialog.address_input.setText("invalid")
        assert not dialog.is_valid()
```

Use mocking for business logic tests, not for UI component tests.

---

## Qt-Specific Testing

### QApplication.processEvents()

Use `QApplication.processEvents()` to process pending Qt events during tests:

```python
def mock_show(dialog_self):
    self._show_called = True
    self._dialog_instance = dialog_self
    QApplication.processEvents()  # Process Qt events
```

**When to use:**
- After creating dialogs to allow Qt to initialize them
- After triggering signals to allow slots to execute
- When testing asynchronous Qt operations

**Caution:** Don't overuse - can make tests slower and hide timing issues.

### QTest Utilities

Use `QTest` for simulating user interactions:

```python
from PySide6.QtTest import QTest

# Wait for Qt events
QTest.qWait(100)  # Wait 100ms for events to process

# Simulate key press
QTest.keyClick(widget, Qt.Key.Key_A)

# Simulate mouse click
QTest.mouseClick(button, Qt.MouseButton.LeftButton)
```

**Example:**
```python
def test_button_click_triggers_action(self):
    """Test that clicking button triggers action."""
    from PySide6.QtTest import QTest

    button = self.widget.find_button()
    with patch.object(self.widget, "on_button_clicked") as mock_handler:
        QTest.mouseClick(button, Qt.MouseButton.LeftButton)
        mock_handler.assert_called_once()
```

### Testing Signals and Slots

Test that signals are emitted and slots are called:

```python
def test_signal_emitted(self):
    """Test that action emits expected signal."""
    signal_received = []

    def slot(value):
        signal_received.append(value)

    self.widget.value_changed.connect(slot)
    self.widget.set_value(42)

    assert signal_received == [42], "Signal should be emitted with new value"
```

### Qt Event Loop Considerations

Some Qt operations require the event loop to run:

```python
def test_delayed_operation(self):
    """Test operation that requires event loop."""
    from PySide6.QtTest import QTest

    self.widget.start_delayed_update()

    # Allow time for delayed operation
    QTest.qWait(150)  # If operation has 100ms delay

    assert self.widget.is_updated()
```

**Note:** Keep waits minimal - if you need long waits, consider refactoring the code to be more testable.

---

## Mock Usage

### Unit Tests: Test One Thing at a Time

**Philosophy:** Write small, focused unit tests that test one piece of functionality in isolation. Mock dependencies to keep tests fast and independent.

```python
# GOOD: Unit test - tests routing logic only
def test_x_key_calls_popup_xref(self):
    """Test that pressing 'x' key calls parse_operand_and_popup_xref_dialog."""
    with patch.object(self.view, "parse_operand_and_popup_xref_dialog") as mock_method:
        key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_X, Qt.KeyboardModifier.NoModifier)
        self.view.keyPressEvent(key_event)

        mock_method.assert_called_once()

# BAD: Integration test - tests multiple layers at once
def test_x_key_opens_dialog(self):
    """Test that pressing 'x' key opens XRef dialog."""
    # This tests keyPressEvent AND parse_operand_and_popup_xref_dialog AND popup_xref_dialog
    # If it fails, you don't know which piece broke
    key_event = QKeyEvent(...)
    self.view.keyPressEvent(key_event)
    assert self._dialog_instance is not None  # Which method failed?
```

### Separate Concerns in Tests

Break down functionality into separate unit tests:

**Example: Testing keyboard shortcuts and dialogs**

1. **Routing test**: Mock the method being called, verify the routing works
2. **Method test**: Call the method directly, verify its behavior

```python
# Test 1: Keyboard routing
def test_g_key_calls_popup_jumpto(self):
    """Test that 'g' key routes to popup_jumpto_dialog."""
    with patch.object(self.view, "popup_jumpto_dialog") as mock_popup:
        key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_G, Qt.KeyboardModifier.NoModifier)
        self.view.keyPressEvent(key_event)
        mock_popup.assert_called_once()

# Test 2: Dialog creation
def test_popup_jumpto_dialog(self):
    """Test that popup_jumpto_dialog creates JumpTo dialog."""
    self.view.popup_jumpto_dialog()
    assert isinstance(self._dialog_instance, JumpTo)
```

**Benefits:**
- Small, focused tests that test one thing
- Clear failure messages (you know exactly what broke)
- Fast execution (mocked dependencies)
- Tests can be run independently
- Easy to maintain and understand

This principle applies to **all code**, not just dialogs:
- Menu actions → Methods they call
- Button clicks → Event handlers
- Event handlers → Business logic
- Business logic → Data access

### Use MagicMock for Complex Objects

When you need to create mock objects with specific attributes:

```python
mock_operand = MagicMock()
mock_operand.is_constant = True
mock_operand.constant_value = 0x2000
mock_operand.variable = None
```

### Testing Third-Party Library Integration

When testing code that uses third-party libraries, test **your integration** with the library, not the library itself:

```python
# GOOD: Test that your code correctly uses the library
def test_set_filter_text_fuzzy_matches_with_typos(self):
    """Test that fuzzy matching finds items even with typos."""
    cmd1 = BasicCommand("cmd1", "Test Command", MagicMock())
    cmd2 = BasicCommand("cmd2", "Other Command", MagicMock())
    self.command_manager.register_command(cmd1)
    self.command_manager.register_command(cmd2)

    model = CommandPaletteModel(self.mock_workspace)
    # "Tst Commnd" should fuzzy match "Test Command" (using thefuzz library)
    model.set_filter_text("Tst Commnd")

    filtered_items = [model.data(model.index(i, 0)) for i in range(model.rowCount())]
    captions = [model.get_caption_for_item(item) for item in filtered_items if item is not None]

    # Verify the integration works
    assert any("Test Command" in caption for caption in captions)

# BAD: Testing the library's internal algorithm
def test_fuzzy_matching_score_calculation(self):
    """DON'T test thefuzz's scoring algorithm - that's the library's job."""
    # This tests thefuzz, not our code
    from thefuzz import fuzz
    assert fuzz.ratio("Test", "Tst") == 80  # Implementation detail of thefuzz
```

**What to test:**
- ✅ Your code correctly calls the library API
- ✅ Results are used correctly in your application
- ✅ Edge cases in your integration (empty queries, no matches, etc.)

**What NOT to test:**
- ❌ Library's internal algorithms or scoring
- ❌ Exact ranking order (implementation detail)
- ❌ Library's edge cases (trust the library's own tests)

**Real-world example:** Command palette fuzzy matching uses `thefuzz.process.extract()`:
- We test that typos, partial matches, and abbreviations work
- We don't test the exact similarity scores or ranking algorithm
- See [test_command_palette.py](test_command_palette.py) for examples

### Aim for 100% Coverage of Test Code Itself

Test code should verify all setup and assumptions - don't use conditionals that silently pass when expected conditions aren't met.

**Test Smell - Silent Pass:**
```python
# BAD - Test silently passes if cmd is not in items
def test_data_returns_item(self):
    cmd = BasicCommand("test_cmd", "Test Command", MagicMock())
    self.command_manager.register_command(cmd)

    model = CommandPaletteModel(self.mock_workspace)
    items = model.get_items()

    if cmd in items:  # ❌ Silent pass if cmd is missing!
        row = items.index(cmd)
        index = model.index(row, 0)
        data = model.data(index)
        assert data == cmd
```

**Proper Test - Explicit Assertion:**
```python
# GOOD - Test fails if cmd is not in items
def test_data_returns_item(self):
    cmd = BasicCommand("test_cmd", "Test Command", MagicMock())
    self.command_manager.register_command(cmd)

    model = CommandPaletteModel(self.mock_workspace)
    items = model.get_items()

    assert cmd in items  # ✅ Explicit assertion - test fails if missing
    row = items.index(cmd)
    index = model.index(row, 0)
    data = model.data(index)
    assert data == cmd
```

**Why this matters:**
- Tests should fail loudly when expectations aren't met
- Conditionals in tests often hide bugs or incorrect assumptions
- Every line of test setup should be verified with assertions
- Silent passes give false confidence in test coverage

**When conditionals ARE acceptable:**
- Defensive cleanup in `tearDown()` methods (e.g., `if hasattr(self, "dialog")`)
- Platform-specific test logic (e.g., `if sys.platform == "linux"`)
- Parametrized tests with different code paths

**Real-world impact:** Fixing 3 test smells in [test_command_palette.py](test_command_palette.py) improved pylint score from 8.94/10 to 10.00/10.

### Parallel with Statements for Multiple Patches

Use parentheses for multiple context managers:

```python
with (
    patch.object(self.instance.breakpoint_mgr, "toggle_exec_breakpoint") as mock_toggle,
    patch.object(self.view, "refresh"),
):
    self.view._insn_menu._toggle_breakpoint()
    mock_toggle.assert_called_once_with(0x1000)
```

---

## Type Safety

### Assert Optional Types Before Access

When accessing attributes/methods on objects typed as `Optional[T]`, assert they're not None:

```python
def test_menu_action(self):
    """Test that menu action works correctly."""
    # _insn_menu is typed as DisasmInsnContextMenu | None
    assert self.view._insn_menu is not None

    self.view._insn_menu.insn_addr = 0x1000
    self.view._insn_menu._toggle_breakpoint()
```

### Add Type Annotations to Class Attributes

When adding attributes that will be assigned different types:

```python
class MyMenu(Menu):
    # Add type annotation at class level
    insn_addr: int | None

    def __init__(self, view):
        super().__init__("", parent=view)
        self.insn_addr = None  # Now pyright understands this can be reassigned
```

### Run Type Checking

Always run `pyright` on your test files:

```bash
pyright tests/test_my_view.py
```

Aim for **0 errors** (except unavoidable import errors from external packages).

---

## Code Quality

### Linting

Run `pylint` with the project config:

```bash
pylint --rcfile=/home/matt/work/angr/angr-dev/pylintrc tests/test_my_view.py
```

**Goal: 10.00/10 score**

### Code Style

Run `ruff`:

```bash
ruff check tests/test_my_view.py
```

**Goal: 0 errors**

### Import Order

Follow PEP 8 import ordering:

```python
# 1. Standard library
import unittest
from unittest.mock import MagicMock, patch

# 2. Third-party (including test utilities)
from common import ProjectOpenTestCase
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent

# 3. Local/project imports
from angrmanagement.ui.dialogs.jumpto import JumpTo
from angrmanagement.ui.views.disassembly_view import DisassemblyView
```

### Avoid Redundant Comments

Don't add comments that simply restate the code:

```python
# BAD
with patch.object(self.view, "popup_jumpto") as mock_popup:
    # Call keyPressEvent with 'g' key
    key_event = QKeyEvent(...)
    self.view.keyPressEvent(key_event)

    # Assert popup_jumpto was called once
    mock_popup.assert_called_once()

# GOOD (docstring explains what, code is self-evident)
def test_g_key_calls_popup_jumpto(self):
    """Test that pressing 'g' key calls popup_jumpto_dialog."""
    with patch.object(self.view, "popup_jumpto_dialog") as mock_popup:
        key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_G, Qt.KeyboardModifier.NoModifier)
        self.view.keyPressEvent(key_event)

        mock_popup.assert_called_once()
```

### Common Pylint Issues in Tests

#### Acceptable Pylint Disables for Test Files

Add this at the top of test files (line 4):

```python
# pylint: disable=no-self-use
```

**`no-self-use`**: Test methods often don't use `self` but still need to be methods for pytest/unittest to discover them.

**Required docstrings:**
- All test classes must have docstrings (even if they just restate the class name)
- All test methods must have docstrings (even if they just restate the method name)
- Consistency is more important than avoiding redundancy
- Docstrings help with test discovery, IDE tooltips, and test reports

**Never disable:**
- `missing-function-docstring` - Required for all test methods
- `missing-class-docstring` - Required for all test classes

#### Empty Classes Don't Need `pass`

Classes with docstrings don't need `pass` statements:

```python
# BAD - unnecessary-pass warning
class DummyView:
    """Lightweight dummy view."""
    pass

# GOOD
class DummyView:
    """Lightweight dummy view."""
```

---

## Coverage Goals

### Aim for 100% Code Coverage

For each method you test, ensure all code paths are covered:

```python
def parse_operand_and_popup_xref_dialog(self, ins_addr, operand):
    if operand is not None:
        if operand.variable is not None:
            # Path 1: Variable - test_with_variable
            self.popup_xref_dialog(addr=ins_addr, variable=operand.variable)
        elif operand.is_constant:
            # Path 2: Constant - test_with_constant
            self.popup_xref_dialog(addr=ins_addr, dst_addr=operand.constant_value)
        elif operand.is_constant_memory:
            # Path 3: Constant memory - test_with_constant_memory
            self.popup_xref_dialog(addr=ins_addr, dst_addr=operand.constant_memory_value)
    # Path 4: None - test_with_none_operand
```

### Test Edge Cases

Don't just test the happy path:
- Test with `None` values
- Test with empty collections
- Test error conditions
- Test boundary values

---

## Common Pitfalls

### 1. Tests That Depend on Execution Order

**BAD:**
```python
class TestBad(unittest.TestCase):
    def test_1_create_user(self):
        self.user = User("alice")  # Class attribute!

    def test_2_user_has_name(self):
        assert self.user.name == "alice"  # Depends on test_1 running first!
```

**GOOD:**
```python
class TestGood(unittest.TestCase):
    def setUp(self):
        self.user = User("alice")  # Fresh for each test

    def test_user_has_name(self):
        assert self.user.name == "alice"  # Independent
```

**Why:** Tests should be independent. pytest may run tests in any order.

### 2. Shared Mutable State Between Tests

**BAD:**
```python
class TestBad(unittest.TestCase):
    shared_list = []  # Class-level mutable state!

    def test_a(self):
        self.shared_list.append(1)
        assert len(self.shared_list) == 1

    def test_b(self):
        # Fails if test_a ran first!
        assert len(self.shared_list) == 0
```

**GOOD:**
```python
class TestGood(unittest.TestCase):
    def setUp(self):
        self.my_list = []  # Fresh instance per test

    def test_a(self):
        self.my_list.append(1)
        assert len(self.my_list) == 1
```

**Why:** Each test should start with a clean state.

### 3. Not Cleaning Up Resources

**BAD:**
```python
def test_opens_file(self):
    f = open("test.txt", "w")
    f.write("data")
    # File not closed! May cause issues in other tests
```

**GOOD:**
```python
def test_opens_file(self):
    with open("test.txt", "w") as f:
        f.write("data")
    # File automatically closed

# Or use addCleanup:
def test_opens_file(self):
    f = open("test.txt", "w")
    self.addCleanup(f.close)
    f.write("data")
```

**Why:** Unclosed resources can leak and affect other tests.

### 4. Testing Implementation Details

**BAD:**
```python
def test_sorts_using_quicksort(self):
    """Test that sort uses quicksort algorithm."""
    with patch('module._quicksort') as mock_quicksort:
        result = my_sort([3, 1, 2])
        mock_quicksort.assert_called()  # Testing HOW it works
```

**GOOD:**
```python
def test_sorts_correctly(self):
    """Test that sort produces correct output."""
    result = my_sort([3, 1, 2])
    assert result == [1, 2, 3]  # Testing WHAT it does
```

**Why:** Tests should verify behavior, not implementation. If you change the algorithm, the test shouldn't break.

### 5. Over-Mocking

**BAD:**
```python
def test_calculates_total(self):
    with (
        patch.object(calculator, 'add') as mock_add,
        patch.object(calculator, 'multiply') as mock_mult,
        patch.object(calculator, 'format_currency') as mock_format,
    ):
        mock_add.return_value = 100
        mock_mult.return_value = 200
        mock_format.return_value = "$200"
        result = calculator.calculate_total(10, 20)
        # You're testing the mocks, not the real code!
```

**GOOD:**
```python
def test_calculates_total(self):
    # Test actual calculation logic
    result = calculator.calculate_total(10, 20)
    assert result == 200
```

**Why:** Over-mocking makes tests pass without testing real code. Mock at boundaries, not internal logic.

### 6. Catching Too Broad Exceptions

**BAD:**
```python
def test_handles_error(self):
    try:
        risky_operation()
        assert False, "Should raise exception"
    except Exception:  # Catches EVERYTHING, even assertion errors!
        pass
```

**GOOD:**
```python
def test_handles_error(self):
    with pytest.raises(SpecificError):
        risky_operation()

# Or with unittest:
def test_handles_error(self):
    with self.assertRaises(SpecificError):
        risky_operation()
```

**Why:** Catching broad exceptions can hide unexpected errors.

### 7. Not Using Fresh View Instances

**BAD:**
```python
class TestView(ProjectOpenTestCase):
    @classmethod
    def setUpClass(cls):
        cls.view = MyView(...)  # Shared across ALL tests!

    def test_a(self):
        self.view.do_something()
        # State persists to test_b!
```

**GOOD:**
```python
class TestView(ProjectOpenTestCase):
    def setUp(self):
        super().setUp()
        self.view = MyView(...)  # Fresh for each test

    def tearDown(self):
        self.view.close()
        del self.view
        super().tearDown()
```

**Why:** Tests should be isolated. Fresh instances prevent state leakage.

---

## Naming Conventions

### Test Method Names

Use descriptive names that explain **what** is being tested:

```python
# GOOD
def test_parse_operand_and_popup_xref_dialog_with_constant_memory(self):
    """Test that parse_operand_and_popup_xref_dialog handles constant_memory operand."""

# BAD
def test_parse_operand_3(self):
    """Test parse_operand."""
```

### Test Class Names

Use clear, descriptive class names:
- `TestPopupDialogs` - Tests for popup dialog methods
- `TestKeyboardShortcuts` - Tests for keyboard event handling
- `TestContextMenus` - Tests for context menu behavior

---

## Complete Example

Here's a complete example following all best practices (using `ProjectOpenTestCase` since DisassemblyView requires a loaded project):

```python
"""
Test cases for DisassemblyView.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from common import ProjectOpenTestCase
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QApplication, QDialog

from angrmanagement.ui.dialogs.jumpto import JumpTo
from angrmanagement.ui.views.disassembly_view import DisassemblyView


class TestDisassemblyViewBase(ProjectOpenTestCase):
    """Base class with shared view setup for DisassemblyView tests."""

    def setUp(self):
        super().setUp()
        self.disasm_view = DisassemblyView(self.workspace, "center", self.instance)

    def tearDown(self):
        if hasattr(self, "disasm_view"):
            self.disasm_view.close()
            del self.disasm_view
        super().tearDown()


class TestPopupDialogs(TestDisassemblyViewBase):
    """Test popup_*_dialog methods that create and show dialogs."""

    def setUp(self):
        super().setUp()

        self._show_called = False
        self._dialog_instance = None

        def mock_show(dialog_self):
            self._show_called = True
            self._dialog_instance = dialog_self

        self._show_patcher = patch("PySide6.QtWidgets.QDialog.show", mock_show)
        self._show_patcher.start()
        self.addCleanup(self._show_patcher.stop)

    def test_popup_jumpto_dialog(self):
        """Test that popup_jumpto_dialog creates and shows JumpTo dialog (non-modal)."""
        self.disasm_view.popup_jumpto_dialog()

        assert self._show_called, "JumpTo dialog should be shown with .show()"
        assert isinstance(self._dialog_instance, JumpTo)
        self._dialog_instance.close()


class TestKeyboardShortcuts(TestDisassemblyViewBase):
    """Test keyboard shortcut routing in keyPressEvent."""

    def test_g_key_calls_popup_jumpto(self):
        """Test that pressing 'g' key calls popup_jumpto_dialog."""
        with patch.object(self.disasm_view, "popup_jumpto_dialog") as mock_popup:
            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_G, Qt.KeyboardModifier.NoModifier)
            self.disasm_view.keyPressEvent(key_event)

            mock_popup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
```

---

## Commit Messages

### Format

Use focused commits with descriptive messages that include a functional area prefix:

```
<FunctionalArea>: <Brief description>

[Optional longer description if needed]
```

### Functional Area Prefixes

Use the component being tested:
- `DisassemblyView: ` - For DisassemblyView tests
- `HexView: ` - For HexView tests
- `CodeView: ` - For CodeView tests
- `QPropertyEditor: ` - For widget tests
- `Tests: ` - For general test infrastructure changes

### Good Examples

```
DisassemblyView: Test pressing X key shows cross-references

DisassemblyView: Add tests for context menu actions

HexView: Test G key opens jump-to dialog

Tests: Add Qt-specific testing patterns to guide

QPropertyEditor: Test value validation for integer properties
```

### Bad Examples

```
# BAD - No functional area prefix
Add tests

# BAD - Too vague
Fix tests

# BAD - Not descriptive enough
Update test_disassembly_view.py

# BAD - Too much detail in short message
DisassemblyView: Add comprehensive test suite covering all keyboard shortcuts including G for jump-to, X for cross-references, semicolon for comments, and N for rename label functionality

# BAD - Including co-author tags (don't use these)
DisassemblyView: Test X key

Co-Authored-By: Someone <email>
```

### Guidelines

**Keep it focused:**
- One logical change per commit
- If adding multiple test classes, consider separate commits
- Group related tests together (e.g., all keyboard shortcut tests)

**Be descriptive:**
- Short message should explain what was tested
- Someone should understand what the commit does without reading the diff

**Use imperative mood:**
- "Test X key behavior" not "Tests X key behavior" or "Testing X key behavior"
- Think: "This commit will: Test X key behavior"

**Keep short messages under 72 characters:**
- Ensures readability in git logs
- Put additional details in the body if needed

### Examples by Task

**Adding new test methods:**
```
DisassemblyView: Test parse_operand handles constant_memory
```

**Refactoring tests:**
```
Tests: Separate keyboard shortcuts from dialog tests
```

**Fixing test issues:**
```
DisassemblyView: Fix type errors in context menu tests
```

**Adding test infrastructure:**
```
Tests: Add base class for shared view setup
```

---

## Checklist

Before submitting tests, verify:

- [ ] Appropriate base class chosen (simplest that provides what you need)
- [ ] Tests organized into logical test classes
- [ ] Base class handles shared setup/teardown
- [ ] All test classes and methods have docstrings
- [ ] Appropriate test type chosen:
  - Unit tests for business logic (mock dependencies)
  - Component tests for UI widgets (test actual behavior)
  - Integration tests only for critical end-to-end paths
- [ ] Dependencies mocked appropriately to keep tests fast and isolated
- [ ] No test smells: assertions not wrapped in conditionals (no silent passes)
- [ ] Optional types have `assert X is not None` before access
- [ ] Import order follows PEP 8
- [ ] No redundant comments
- [ ] `pylint` score: 10.00/10
- [ ] `ruff check` passes with 0 errors
- [ ] `pyright` passes with 0 errors (except unavoidable imports)
- [ ] All tests pass: `pytest tests/test_my_view.py -v`
- [ ] 100% code coverage for tested methods
- [ ] Commit message follows format: `<Component>: <Description>`

---

## Running Tests

### Virtual Environment Setup

Activate the angr virtual environment before running tests:

```bash
source ~/.virtualenvs/angr/bin/activate
```

All commands below assume the virtual environment is activated.

### Basic Test Commands

```bash
# Run specific test file
pytest tests/test_disassembly_view.py -v

# Run specific test class
pytest tests/test_disassembly_view.py::TestPopupDialogs -v

# Run specific test method
pytest tests/test_disassembly_view.py::TestPopupDialogs::test_popup_jumpto_dialog -v

# Type check
pyright tests/test_disassembly_view.py

# Lint
pylint --rcfile=/home/matt/work/angr/angr-dev/pylintrc tests/test_disassembly_view.py
ruff check tests/test_disassembly_view.py
```

### Code Coverage

#### Standard Coverage (using pytest-cov)

```bash
# Run with coverage
pytest tests/test_disassembly_view.py --cov=angrmanagement.ui.views.disassembly_view

# Get coverage report with line numbers for missing coverage
pytest tests/test_disassembly_view.py --cov=angrmanagement.ui.views.disassembly_view --cov-report=term-missing
```

#### Coverage Troubleshooting

If pytest-cov fails with crashes (e.g., "Fatal Python error: Aborted" related to pypcode), use coverage.py directly:

```bash
# Run tests with coverage.py (without --source to avoid pypcode crash)
cd /path/to/angr-management
coverage run -m pytest tests/test_my_view.py --no-cov -v

# Combine coverage data if needed (coverage.py creates machine-specific files)
coverage combine

# Generate coverage report for specific module
coverage report -m --include='angrmanagement/ui/views/my_view.py'

# Example: Get coverage for command_palette.py from both test files
coverage run -m pytest tests/test_command_palette.py tests/test_goto_palette.py --no-cov -v
coverage combine
coverage report -m --include='angrmanagement/ui/dialogs/command_palette.py'

# Generate HTML coverage report
coverage html --include="angrmanagement/ui/views/*"
# Open htmlcov/index.html in browser
```

**Key differences from pytest-cov:**
- Use `coverage run -m pytest` instead of `pytest --cov`
- Add `--no-cov` flag to prevent pytest-cov from activating
- Don't use `--source` parameter (causes pypcode crash)
- Use `coverage combine` to merge machine-specific coverage files
- Use `--include` parameter in `coverage report` to filter results

**Note:** Coverage collection may conflict with some native dependencies (pypcode). If you encounter crashes:
1. Run tests without coverage first to verify they pass: `pytest tests/test_my_view.py -v`
2. Use coverage.py directly instead of pytest-cov (see above)
3. Always use `--no-cov` flag when running with `coverage run`
4. Run quality tools (pylint, ruff, pyright) separately - they don't need coverage

### Running All Quality Checks

Run all quality checks in sequence:

```bash
# Activate virtual environment
source ~/.virtualenvs/angr/bin/activate

# Run tests
pytest tests/test_my_view.py -v

# Check code quality
pylint --rcfile=/home/matt/work/angr/angr-dev/pylintrc tests/test_my_view.py
ruff check tests/test_my_view.py
pyright tests/test_my_view.py

# Get coverage (if working)
pytest tests/test_my_view.py --cov=angrmanagement.ui.views.my_view --cov-report=term-missing
```

### Running Tests in Parallel

For faster test execution, use `pytest-xdist` to run tests in parallel:

```bash
# Run tests in parallel using all available CPU cores
pytest tests/test_command_palette.py tests/test_main_window.py -n auto

# Specify number of workers explicitly
pytest tests/ -n 4
```

**Performance improvement example:**
- Sequential: `pytest tests/test_command_palette.py tests/test_main_window.py` → 40.40 seconds
- Parallel: `pytest tests/test_command_palette.py tests/test_main_window.py -n auto` → 10.13 seconds
- **4x speedup** with 24 workers on a multi-core system

**When to use parallel execution:**
- ✅ Running full test suite or multiple test files
- ✅ CI/CD pipelines with multi-core runners
- ✅ Local development when running many tests
- ❌ Debugging specific test failures (harder to read output)
- ❌ Tests with shared state or race conditions (most angr-management tests are safe)

**Compatibility:**
- Works with Qt tests (AngrManagementTestCase, ProjectOpenTestCase)
- Each worker gets its own QApplication instance
- Tests must be independent (no shared state)

---

## Debugging Failing Tests

### Running a Single Test

Narrow down failures by running one test at a time:

```bash
# Run specific test method
pytest tests/test_disassembly_view.py::TestPopupDialogs::test_popup_jumpto_dialog -v

# Run specific test class
pytest tests/test_disassembly_view.py::TestPopupDialogs -v

# Run all tests matching a pattern
pytest tests/ -k "jumpto" -v
```

### Useful pytest Flags

```bash
# Stop on first failure (don't run remaining tests)
pytest tests/test_my_view.py -x

# Show print statements and logging output
pytest tests/test_my_view.py -s

# Drop into debugger on failure
pytest tests/test_my_view.py --pdb

# Show local variables in tracebacks
pytest tests/test_my_view.py -l

# Run last failed tests only
pytest --lf

# Run failed tests first, then others
pytest --ff
```

### Reading pytest Output

When a test fails, pytest shows:

```
FAILED tests/test_view.py::TestClass::test_method - AssertionError: assert False
```

Read from bottom up:
1. **Failure location**: `test_view.py::TestClass::test_method`
2. **Failure type**: `AssertionError`
3. **Failure message**: `assert False`

Look at the traceback to see:
- Which line failed
- Values of variables at failure point
- Call stack leading to failure

### Using the Debugger

Add breakpoint in test:

```python
def test_something(self):
    result = do_calculation()
    breakpoint()  # Execution stops here
    assert result == expected
```

Or use `--pdb` flag to auto-break on failures:

```bash
pytest tests/test_my_view.py::test_something --pdb
```

Common pdb commands:
- `l` (list) - Show code around current line
- `p variable` (print) - Print variable value
- `n` (next) - Execute next line
- `s` (step) - Step into function
- `c` (continue) - Continue execution
- `q` (quit) - Exit debugger

### Adding Debug Output

Temporarily add print statements:

```python
def test_something(self):
    result = calculate()
    print(f"DEBUG: result = {result}")  # Shows with -s flag
    assert result == 42
```

Run with `-s` to see output:
```bash
pytest tests/test_my_view.py -s
```

### Checking Test Isolation

If a test fails only when run with other tests:

```bash
# Test fails when run with full suite
pytest tests/test_my_view.py  # FAIL

# But passes when run alone
pytest tests/test_my_view.py::TestClass::test_method  # PASS
```

This indicates **test isolation issues** - tests are affecting each other. Check for:
- Shared class-level state
- Global variables
- Uncleaned resources
- Mock patches not cleaned up

### Common Failure Patterns

**"AttributeError: 'NoneType' object has no attribute 'X'"**
- Object is None when it shouldn't be
- Check initialization in setUp()
- Check return values of mocked methods

**"assert mock.assert_called_once() raised AssertionError"**
- Method wasn't called, or was called multiple times
- Check that you're mocking the right target
- Use `mock.call_count` to see how many times it was called

**"QWidget: Must construct a QApplication before a QWidget"**
- Qt not initialized
- Use `AngrManagementTestCase` or `ProjectOpenTestCase` base class

**Test passes locally but fails in CI**
- Timing issues (need QTest.qWait())
- Missing dependencies
- Environment differences

---

## Testing Qt Components

### Testing Event Filters

Qt event filters require special handling due to event propagation patterns. Example from `test_main_window.py`:

```python
def test_double_shift_triggers_goto_palette(self):
    """Test that pressing Shift twice quickly opens goto palette."""
    with patch.object(self.main, "show_goto_palette") as mock_show:
        mock_window = MagicMock(spec=QWindow)
        mock_window.modality.return_value = Qt.WindowModality.NonModal
        mock_widget = QWidget()

        key_event = QKeyEvent(
            QKeyEvent.Type.KeyPress, Qt.Key.Key_Shift, Qt.KeyboardModifier.NoModifier
        )

        # Simulate Qt event propagation: QWindow -> QWidget
        self.event_filter.eventFilter(mock_window, key_event)  # Phase 1: Mark event
        self.event_filter.eventFilter(mock_widget, key_event)  # Phase 2: Process event
```

**Why two calls?** Many event filters use two-phase detection:
1. **QWindow call** - Detects unique key presses at window level
2. **QWidget call** - Processes the event at widget level

This prevents duplicate processing when events propagate through multiple widgets. Always check the implementation to understand the event flow.

### Test File Organization by Component

Organize tests by the **component being tested**, not the component being invoked:

**Example:** Keyboard shortcuts invoke the command palette, but event filters are MainWindow components:
- `test_command_palette.py` - Command palette dialogs, models, delegates
- `test_main_window.py` - MainWindow components (event filters, shortcuts)
- Keep integration tests with the feature they integrate (e.g., `show_command_palette()` stays with palette tests)

### Forcing Qt to Render for Coverage

Qt's rendering is lazy and optimized. Simply calling `dialog.show()` and `QApplication.processEvents()` doesn't guarantee Qt will actually paint everything. To ensure paint delegate methods execute during tests:

```python
def test_dialog_renders_items_with_icons(self):
    """Test that dialog renders items with icons."""
    model = ModelWithIcons(mock_workspace)
    dialog = PaletteDialog(model, parent=self.main)
    delegate = PaletteItemDelegate(display_icons=True)
    dialog._view.setItemDelegate(delegate)

    # Show dialog and trigger initial rendering
    dialog.show()
    QApplication.processEvents()

    # Force Qt to actually paint all items (critical for coverage!)
    dialog._view.viewport().repaint()
    QApplication.processEvents()

    dialog.close()
```

**Why this matters:**
- `dialog.show()` + `processEvents()` may not execute all paint code paths
- Qt optimizes rendering and may skip painting items not visible
- `viewport().repaint()` forces immediate painting of the viewport
- Essential for achieving coverage of custom paint delegate methods

**Real-world impact:**
- Command palette tests: 95% → 98% coverage after adding `repaint()`
- Icon rendering paths (lines 202, 204-205) only covered after forcing repaint
- See [test_command_palette.py](test_command_palette.py) `test_dialog_renders_items_with_*` tests

---

## Real-World Examples

### Command Palette Tests

Files: `test_command_palette.py` (65 tests) + `test_main_window.py` (7 tests) = **72 tests total**

**test_command_palette.py - Test distribution by base class:**
- **29 tests (45%)** - `unittest.TestCase` - Pure Python/lightweight mocks
  - Command classes, models with mocked workspace
  - Includes fuzzy matching integration tests
  - Run in <1 second
- **25 tests (38%)** - `AngrManagementTestCase` - Need Qt/UI
  - Dialogs, integration tests
  - Run in ~20 seconds
- **11 tests (17%)** - `ProjectOpenTestCase` - Need angr project
  - Tests requiring loaded binary
  - Run in ~15 seconds

**test_main_window.py - Keyboard shortcut tests:**
- **7 tests (100%)** - `AngrManagementTestCase` - Need Qt/UI
  - Event filters for Ctrl+Shift+P and Shift+Shift
  - Run in ~3 seconds

**Key techniques demonstrated:**
- Creating minimal test dependencies instead of using `self.main`
- Using real `CommandManager` instead of mocking
- Using dummy classes for type parameters (DummyView vs DisassemblyView)
- Proper use of MagicMock for workspace/view_manager
- Avoiding test smells (replacing `if item in items:` with `assert item in items`)
- Coverage-guided test development (98% coverage of command_palette.py)
- Forcing Qt to render with `viewport().repaint()` for paint delegate coverage
- Testing Qt event filters with proper event propagation
- Organizing tests by architectural component
- Testing third-party library integration (fuzzy matching with `thefuzz`)

**Quality metrics:**
- Pylint: 10.00/10 (improved from 8.94/10 by fixing test smells)
- Ruff: 0 errors
- Pyright: 0 errors, 0 warnings
- Sequential execution: 40 seconds across both files
- Parallel execution (`-n auto`): 10 seconds (4x speedup)
- Individual test suites: <1s for pure Python tests
- CI/CD builds faster with isolated unit tests and parallel execution

See these files for concrete examples of each pattern.

---

## Additional Resources

- [unittest documentation](https://docs.python.org/3/library/unittest.html)
- [unittest.mock documentation](https://docs.python.org/3/library/unittest.mock.html)
- [pytest documentation](https://docs.pytest.org/)
- [PySide6 documentation](https://doc.qt.io/qtforpython-6/)
- [QTest documentation](https://doc.qt.io/qt-6/qtest.html)
- **Example:** [test_command_palette.py](test_command_palette.py) - Comprehensive real-world example
