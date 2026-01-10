# TUI Codebase Code Quality Evaluation

**Evaluation Date:** 2026-01-10
**Evaluator:** Senior Python Developer / QA Engineer
**Codebase:** `/Users/ic/cptc11/python/tui/`
**Framework:** Textual TUI Framework

---

## Executive Summary

The TUI codebase demonstrates a solid foundation for a security toolsmith terminal application built with the Textual framework. The code shows good architectural decisions and follows many Python best practices. However, there are several areas requiring improvement, particularly around error handling robustness, import consistency, and testability patterns.

**Overall Score: 7.2/10**

| Category | Score | Status |
|----------|-------|--------|
| Code Organization | 8/10 | Good |
| Textual Best Practices | 7/10 | Satisfactory |
| Error Handling | 5/10 | Needs Improvement |
| Type Hints | 8/10 | Good |
| Documentation | 7/10 | Satisfactory |
| Performance | 7/10 | Satisfactory |
| Testability | 6/10 | Needs Improvement |
| Maintainability | 7/10 | Satisfactory |

---

## 1. Code Organization

### Strengths

**Module Structure:**
The codebase follows a logical package structure with clear separation of concerns:

```
tui/
├── app.py              # Main application entry
├── screens/            # Screen components
├── widgets/            # Reusable widgets
├── visualizers/        # Visualization components
├── styles/             # TCSS stylesheets
├── utils/              # Helper functions
└── components/         # Complex UI components
```

**Good Example - Clean Screen Import Pattern:**
```python
# /Users/ic/cptc11/python/tui/screens/__init__.py
from .dashboard import DashboardScreen
from .tool_config import ToolConfigScreen

__all__ = ["DashboardScreen", "ToolConfigScreen"]
```

### Issues Found

**Issue 1.1: Circular Import Avoidance Causes Poor Separation**

The `DashboardScreen` class is defined in `app.py` rather than `screens/dashboard.py`, which creates an architectural inconsistency. The `screens/dashboard.py` file only contains a placeholder comment.

**Location:** `/Users/ic/cptc11/python/tui/app.py` (lines 141-330)

**Current Code:**
```python
# screens/dashboard.py
"""
Dashboard Screen
...
This module re-exports the DashboardScreen from app.py for modular imports.
"""
# For actual use, import from the app module:
# from ..app import DashboardScreen
```

**Recommended Fix:**
Move `DashboardScreen` to its own module and use proper dependency injection or protocol classes to avoid circular imports:

```python
# screens/dashboard.py
from __future__ import annotations
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ..app import SecurityTool

class ToolProvider(Protocol):
    """Protocol for providing tools."""
    @property
    def tools(self) -> list: ...

class DashboardScreen(Screen):
    def __init__(self, tool_provider: ToolProvider) -> None:
        super().__init__()
        self._tool_provider = tool_provider
```

**Issue 1.2: Inconsistent Package Exports**

The `widgets/__init__.py` exports `StatusBar` but the actual class is named `ToolsmithStatusBar`.

**Location:** `/Users/ic/cptc11/python/tui/widgets/__init__.py` (line 5)

**Current Code:**
```python
from .status_bar import StatusBar  # This will fail - class is ToolsmithStatusBar
```

**Recommended Fix:**
```python
from .status_bar import ToolsmithStatusBar as StatusBar
# OR
from .status_bar import ToolsmithStatusBar

__all__ = ["ToolPanel", "OutputViewer", "ToolsmithStatusBar"]
```

**Issue 1.3: God Object Anti-Pattern in app.py**

The `app.py` file is 375 lines and contains multiple responsibilities: data models (`SecurityTool`), default data (`DEFAULT_TOOLS`), screen definition (`DashboardScreen`), and application class (`ToolsmithApp`).

**Recommended Refactoring:**
```
models/
├── __init__.py
├── security_tool.py      # SecurityTool dataclass
└── default_tools.py      # DEFAULT_TOOLS list
```

---

## 2. Textual Best Practices

### Strengths

**Good Use of Reactive Attributes:**
```python
# /Users/ic/cptc11/python/tui/widgets/tool_panel.py
selected_tool: reactive[Optional["SecurityTool"]] = reactive(None)
filter_category: reactive[Optional[str]] = reactive(None)
```

**Proper Message Pattern:**
```python
# /Users/ic/cptc11/python/tui/widgets/tool_panel.py
class ToolSelected(Message):
    """Message sent when a tool is selected from the panel."""
    def __init__(self, tool: "SecurityTool") -> None:
        self.tool = tool
        super().__init__()
```

**Good CSS-in-Widget Pattern:**
```python
# /Users/ic/cptc11/python/tui/widgets/tool_panel.py
class ToolItem(Static):
    DEFAULT_CSS = """
    ToolItem {
        height: 3;
        padding: 0 1;
        ...
    }
    """
```

### Issues Found

**Issue 2.1: Improper Worker Pattern Usage**

The code uses `asyncio.create_task` with `call_later` instead of Textual's built-in worker system.

**Location:** `/Users/ic/cptc11/python/tui/app.py` (lines 241-330)

**Current Code:**
```python
def run_tool_async(self, tool: SecurityTool, params: Dict[str, str]) -> None:
    """Run tool execution in a worker."""
    async def execute_tool() -> str:
        # ...

    def on_complete(result: str) -> None:
        # ...

    # Uses call_later with asyncio.create_task - NOT recommended
    self.app.call_later(lambda: asyncio.create_task(self._execute_and_callback(execute_tool, on_complete)))
```

**Recommended Fix - Use Textual Workers:**
```python
from textual.worker import Worker, WorkerState

def run_tool_async(self, tool: SecurityTool, params: Dict[str, str]) -> None:
    """Run tool execution in a worker."""
    self.run_worker(
        self._execute_tool(tool, params),
        name=f"tool_{tool.name}",
        exit_on_error=False
    )

@work(exclusive=True)
async def _execute_tool(self, tool: SecurityTool, params: Dict[str, str]) -> str:
    """Execute tool as a Textual worker."""
    await asyncio.sleep(2)
    # ... tool execution logic ...
    return output

def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
    """Handle worker state changes."""
    if event.state == WorkerState.SUCCESS:
        self._handle_tool_success(event.worker.result)
    elif event.state == WorkerState.ERROR:
        self.log_message(f"Error: {event.worker.error}", level="error")
```

**Issue 2.2: Missing `can_focus` Property Configuration**

Several widgets that should be focusable don't properly declare `can_focus` in class definition.

**Location:** `/Users/ic/cptc11/python/tui/widgets/tool_panel.py` (line 80)

**Current Code:**
```python
def __init__(self, tool: "SecurityTool", *args, **kwargs) -> None:
    super().__init__(*args, **kwargs)
    self.tool = tool
    self.can_focus = True  # Set in __init__, not as class attribute
```

**Recommended Fix:**
```python
class ToolItem(Static, can_focus=True):
    """A clickable tool item in the tool list."""
    # can_focus is now a class-level declaration
```

**Issue 2.3: Suboptimal Query Pattern**

Repeated `query_one` calls in methods could be cached.

**Location:** `/Users/ic/cptc11/python/tui/widgets/status_bar.py` (multiple locations)

**Current Code:**
```python
def _update_duration(self) -> None:
    duration_widget = self.query_one("#duration", Static)
    duration_widget.update(...)

def reset(self) -> None:
    # ...
    duration_widget = self.query_one("#duration", Static)
    duration_widget.update(...)
```

**Recommended Fix - Cache Widget References:**
```python
def on_mount(self) -> None:
    """Cache widget references on mount."""
    self._duration_widget = self.query_one("#duration", Static)
    self._clock_widget = self.query_one("#clock", Static)
    self._timer = self.set_interval(1, self._update_clock)
```

---

## 3. Error Handling

### Critical Issues

**Issue 3.1: Silent Failures in Tool Execution**

The `_execute_and_callback` method catches all exceptions but only logs them, potentially masking critical errors.

**Location:** `/Users/ic/cptc11/python/tui/app.py` (lines 323-330)

**Current Code:**
```python
async def _execute_and_callback(self, coro_func, callback) -> None:
    """Execute coroutine and call callback with result."""
    try:
        result = await coro_func()
        callback(result)
    except Exception as e:
        self.log_message(f"Error: {str(e)}", level="error")
        self.update_status("error")
```

**Issues:**
1. No exception type differentiation
2. Original exception traceback is lost
3. No mechanism for retry or recovery

**Recommended Fix:**
```python
import logging
import traceback

logger = logging.getLogger(__name__)

async def _execute_and_callback(self, coro_func, callback) -> None:
    """Execute coroutine and call callback with result."""
    try:
        result = await coro_func()
        callback(result)
    except asyncio.CancelledError:
        self.log_message("Operation cancelled", level="warning")
        self.update_status("cancelled")
        raise  # Re-raise CancelledError
    except asyncio.TimeoutError:
        self.log_message("Operation timed out", level="error")
        self.update_status("error")
    except ValueError as e:
        self.log_message(f"Invalid input: {e}", level="error")
        self.update_status("error")
    except Exception as e:
        logger.exception("Unexpected error during tool execution")
        self.log_message(f"Unexpected error: {type(e).__name__}: {e}", level="error")
        self.update_status("error")
```

**Issue 3.2: Missing Error Handling in parse_port_range**

The utility function can raise `ValueError` without validation.

**Location:** `/Users/ic/cptc11/python/tui/utils/helpers.py` (lines 65-83)

**Current Code:**
```python
def parse_port_range(port_str: str) -> List[int]:
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))  # Can raise ValueError
        else:
            ports.append(int(part))  # Can raise ValueError
    return ports
```

**Recommended Fix:**
```python
class PortRangeError(ValueError):
    """Error parsing port range string."""
    pass

def parse_port_range(port_str: str) -> List[int]:
    """
    Parse a port range string.

    Raises:
        PortRangeError: If the port string is invalid
    """
    if not port_str or not port_str.strip():
        raise PortRangeError("Empty port string")

    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                start, end = part.split("-", 1)
                start_port, end_port = int(start), int(end)
                if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                    raise PortRangeError(f"Port out of range: {part}")
                if start_port > end_port:
                    raise PortRangeError(f"Invalid range: {part}")
                ports.extend(range(start_port, end_port + 1))
            else:
                port = int(part)
                if not 1 <= port <= 65535:
                    raise PortRangeError(f"Port out of range: {port}")
                ports.append(port)
        except ValueError as e:
            raise PortRangeError(f"Invalid port value in '{part}': {e}")
    return ports
```

**Issue 3.3: Missing Widget Query Error Handling**

`query_one` calls can raise `NoMatches` exception if widget not found.

**Location:** Multiple files

**Example from:** `/Users/ic/cptc11/python/tui/app.py` (line 186-187)

**Current Code:**
```python
def log_message(self, message: str, level: str = "info") -> None:
    output_viewer = self.query_one("#output-viewer", OutputViewer)  # Can raise NoMatches
    output_viewer.log(message, level=level)
```

**Recommended Fix:**
```python
from textual.css.query import NoMatches

def log_message(self, message: str, level: str = "info") -> None:
    try:
        output_viewer = self.query_one("#output-viewer", OutputViewer)
        output_viewer.log(message, level=level)
    except NoMatches:
        # Widget not yet mounted or not found
        self.log.warning(f"OutputViewer not found, message lost: {message}")
```

---

## 4. Type Hints

### Strengths

**Comprehensive Type Annotations:**
```python
# /Users/ic/cptc11/python/tui/widgets/output_viewer.py
def log(
    self,
    message: str,
    level: LogLevel = "info",
    timestamp: Optional[datetime] = None
) -> None:
```

**Good Use of Literal Types:**
```python
# /Users/ic/cptc11/python/tui/widgets/output_viewer.py
LogLevel = Literal["debug", "info", "success", "warning", "error"]
```

**Proper TYPE_CHECKING Usage:**
```python
# /Users/ic/cptc11/python/tui/screens/tool_config.py
if TYPE_CHECKING:
    from ..app import SecurityTool
```

### Issues Found

**Issue 4.1: Missing Return Type Annotations**

Some methods lack return type hints.

**Location:** `/Users/ic/cptc11/python/tui/widgets/tool_panel.py` (lines 87-88)

**Current Code:**
```python
def on_click(self) -> None:
    """Handle click events."""
    self.action_select()

def action_select(self) -> None:  # Good
    ...

def deselect(self) -> None:  # Good
    ...
```

However:

**Location:** `/Users/ic/cptc11/python/tui/visualizers/attack_visualizer.py` (line 174)

```python
def on_mount(self) -> None:  # Good
    """Initialize with sample topology."""
    self._init_sample_topology()
    self._update_topology_display()

def _init_sample_topology(self) -> None:  # Good
    ...

def _update_topology_display(self) -> None:  # Good
    ...
```

Overall type hint coverage is good (estimated 90%+).

**Issue 4.2: Inconsistent Generic Type Usage**

Some reactive attributes use string literals for forward references where direct types could work.

**Location:** `/Users/ic/cptc11/python/tui/widgets/tool_panel.py` (line 170)

**Current Code:**
```python
selected_tool: reactive[Optional["SecurityTool"]] = reactive(None)
```

This is correct for avoiding circular imports, but could be improved with PEP 563:

```python
from __future__ import annotations

selected_tool: reactive[Optional[SecurityTool]] = reactive(None)
```

---

## 5. Documentation

### Strengths

**Good Module-Level Docstrings:**
```python
# /Users/ic/cptc11/python/tui/widgets/output_viewer.py
"""
Output Viewer Widget

A scrollable log viewer that displays tool output with syntax highlighting
and severity-based coloring.
"""
```

**Comprehensive Method Documentation:**
```python
# /Users/ic/cptc11/python/tui/utils/helpers.py
def format_timestamp(dt: Optional[datetime] = None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Format a datetime object.

    Args:
        dt: Datetime to format (defaults to now)
        fmt: Format string

    Returns:
        Formatted timestamp string
    """
```

### Issues Found

**Issue 5.1: Incomplete Widget Feature Documentation**

The `OutputViewer` class mentions planned features without documenting current implementation status.

**Location:** `/Users/ic/cptc11/python/tui/widgets/output_viewer.py` (lines 67-78)

**Current Code:**
```python
class OutputViewer(Widget):
    """
    Output viewer widget for displaying tool execution logs.

    Features:
    - Scrollable log display
    - Color-coded log levels
    - Timestamp for each entry
    - Auto-scroll to latest
    - Search functionality (planned)  # Misleading - not implemented
    - Export capabilities (planned)    # Partially implemented
    """
```

**Recommended Fix:**
```python
class OutputViewer(Widget):
    """
    Output viewer widget for displaying tool execution logs.

    Implemented Features:
        - Scrollable log display
        - Color-coded log levels (debug, info, success, warning, error)
        - Timestamp for each entry
        - Auto-scroll toggle
        - Level-based filtering
        - Plain text export

    Planned Features:
        - Search functionality
        - Rich export formats (JSON, HTML)
    """
```

**Issue 5.2: Missing Docstrings in Key Methods**

Some important methods lack docstrings.

**Location:** `/Users/ic/cptc11/python/tui/visualizers/attack_visualizer.py` (line 287)

**Current Code:**
```python
def _render_event(self, event: AttackEvent) -> None:
    """Render an attack event to the log."""  # Brief but acceptable
    style, icon = self.SEVERITY_STYLES.get(event.severity, ("white", "?"))
    # ...
```

Better example needed at:

**Location:** `/Users/ic/cptc11/python/tui/widgets/status_bar.py` (line 263)

**Current Code:**
```python
def watch_status(self, status: StatusType) -> None:
    """React to status changes."""
    pass  # Handled in update_status
```

This is confusing - the docstring should explain why it exists but does nothing.

**Recommended Fix:**
```python
def watch_status(self, status: StatusType) -> None:
    """
    React to status changes.

    Note:
        This watcher exists for Textual's reactive system but actual
        status updates are handled in update_status() for centralized
        control. This method intentionally does nothing.
    """
    pass
```

---

## 6. Performance

### Strengths

**Efficient Data Structures:**
```python
# /Users/ic/cptc11/python/tui/widgets/tool_panel.py
self._tool_items: Dict[str, ToolItem] = {}  # O(1) lookup
```

**Appropriate Log Limits:**
```python
# /Users/ic/cptc11/python/tui/widgets/output_viewer.py
yield RichLog(
    ...
    max_lines=10000,  # Prevents unbounded memory growth
)
```

### Issues Found

**Issue 6.1: Inefficient Category Grouping on Every Compose**

The tool panel groups tools by category every time `compose()` is called.

**Location:** `/Users/ic/cptc11/python/tui/widgets/tool_panel.py` (lines 183-201)

**Current Code:**
```python
def compose(self) -> ComposeResult:
    """Compose the tool panel layout."""
    yield Label("[b]SECURITY TOOLS[/b]", id="tool-panel-title")

    with ScrollableContainer(id="tool-list-container"):
        # Group tools by category - computed every compose
        categories: Dict[str, List["SecurityTool"]] = {}
        for tool in self.tools:
            if tool.category not in categories:
                categories[tool.category] = []
            categories[tool.category].append(tool)
        # ...
```

**Recommended Fix:**
```python
from functools import cached_property

@cached_property
def _tools_by_category(self) -> Dict[str, List["SecurityTool"]]:
    """Group tools by category (cached)."""
    categories: Dict[str, List["SecurityTool"]] = {}
    for tool in self.tools:
        categories.setdefault(tool.category, []).append(tool)
    return dict(sorted(categories.items()))

def compose(self) -> ComposeResult:
    yield Label("[b]SECURITY TOOLS[/b]", id="tool-panel-title")
    with ScrollableContainer(id="tool-list-container"):
        for category, tools in self._tools_by_category.items():
            yield CategoryHeader(category)
            for tool in tools:
                # ...
```

**Issue 6.2: Potential Memory Leak in Attack Events**

Attack events are stored indefinitely without any pruning mechanism.

**Location:** `/Users/ic/cptc11/python/tui/visualizers/attack_visualizer.py` (lines 277-279)

**Current Code:**
```python
def add_attack_event(self, ...) -> None:
    # ...
    self._events.append(event)  # Unbounded growth
    self.event_count = len(self._events)
```

**Recommended Fix:**
```python
MAX_EVENTS = 10000  # Class constant

def add_attack_event(self, ...) -> None:
    # ...
    self._events.append(event)

    # Prune old events if limit exceeded
    if len(self._events) > self.MAX_EVENTS:
        self._events = self._events[-self.MAX_EVENTS:]

    self.event_count = len(self._events)
```

**Issue 6.3: String Concatenation in Loop**

Building ASCII art using string concatenation in loops is inefficient.

**Location:** `/Users/ic/cptc11/python/tui/utils/helpers.py` (lines 225-277)

The `create_ascii_box` function uses string concatenation which is acceptable for small inputs but could be optimized.

---

## 7. Testability

### Strengths

**Dataclass Usage for Models:**
```python
# /Users/ic/cptc11/python/tui/app.py
@dataclass
class SecurityTool:
    """Represents a security tool available in the application."""
    name: str
    description: str
    command: str
    category: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    is_running: bool = False
```

Dataclasses are easy to instantiate in tests.

**Pure Utility Functions:**
```python
# /Users/ic/cptc11/python/tui/utils/helpers.py
def validate_ip_address(ip: str) -> bool:
    """Validate an IP address."""
    # Pure function - easy to test
```

### Issues Found

**Issue 7.1: Hard-Coded Dependencies in DashboardScreen**

The `DashboardScreen` directly references `DEFAULT_TOOLS`, making it hard to test with mock data.

**Location:** `/Users/ic/cptc11/python/tui/app.py` (line 164)

**Current Code:**
```python
def compose(self) -> ComposeResult:
    # ...
    yield ToolPanel(id="tool-panel", tools=DEFAULT_TOOLS)  # Hard-coded
```

**Recommended Fix - Dependency Injection:**
```python
class DashboardScreen(Screen):
    def __init__(self, tools: Optional[List[SecurityTool]] = None) -> None:
        super().__init__()
        self._tools = tools or DEFAULT_TOOLS

    def compose(self) -> ComposeResult:
        # ...
        yield ToolPanel(id="tool-panel", tools=self._tools)

# In tests:
def test_dashboard_with_mock_tools():
    mock_tools = [SecurityTool(name="Test", ...)]
    screen = DashboardScreen(tools=mock_tools)
```

**Issue 7.2: Missing Interface Abstractions**

The `run_command` function in helpers directly uses `asyncio.create_subprocess_exec`, making it difficult to mock.

**Location:** `/Users/ic/cptc11/python/tui/utils/helpers.py` (lines 127-166)

**Recommended Fix - Introduce Protocol:**
```python
from typing import Protocol

class CommandRunner(Protocol):
    async def run(
        self,
        command: List[str],
        timeout: Optional[float] = None,
        cwd: Optional[Path] = None
    ) -> Tuple[int, str, str]: ...

class AsyncSubprocessRunner:
    """Production command runner using asyncio subprocess."""
    async def run(self, command, timeout=None, cwd=None):
        # Current implementation
        ...

class MockCommandRunner:
    """Test double for command execution."""
    def __init__(self, responses: Dict[str, Tuple[int, str, str]]):
        self.responses = responses

    async def run(self, command, timeout=None, cwd=None):
        key = " ".join(command)
        return self.responses.get(key, (0, "", ""))
```

**Issue 7.3: Side Effects in `__init__`**

The `AttackVisualizer._init_sample_topology` is called in `on_mount`, but sample data shouldn't be created automatically for testing.

**Location:** `/Users/ic/cptc11/python/tui/visualizers/attack_visualizer.py` (lines 174-177)

**Current Code:**
```python
def on_mount(self) -> None:
    """Initialize with sample topology."""
    self._init_sample_topology()  # Always creates sample data
    self._update_topology_display()
```

**Recommended Fix:**
```python
def __init__(self, include_sample_data: bool = True, *args, **kwargs) -> None:
    super().__init__(*args, **kwargs)
    self._events: List[AttackEvent] = []
    self._nodes: Dict[str, NetworkNode] = {}
    self._include_sample_data = include_sample_data

def on_mount(self) -> None:
    """Initialize topology display."""
    if self._include_sample_data:
        self._init_sample_topology()
    self._update_topology_display()
```

---

## 8. Maintainability

### Strengths

**Clear Naming Conventions:**
- Classes: PascalCase (`ToolPanel`, `OutputViewer`)
- Methods: snake_case (`log_message`, `update_status`)
- Constants: SCREAMING_SNAKE_CASE (`DEFAULT_TOOLS`, `STATUS_ICONS`)

**Consistent File Organization:**
Each widget file follows the same pattern: imports, type definitions, dataclasses, main widget class.

### Issues Found

**Issue 8.1: Magic Strings Throughout Codebase**

Status types, log levels, and CSS classes are used as string literals in multiple places.

**Location:** Multiple files

**Example from:** `/Users/ic/cptc11/python/tui/app.py`

```python
self.update_status("ready")      # Magic string
self.update_status("running")    # Magic string
self.log_message(..., level="info")  # Magic string
```

**Recommended Fix - Use Enums:**
```python
from enum import Enum, auto

class Status(str, Enum):
    READY = "ready"
    RUNNING = "running"
    COMPLETE = "complete"
    ERROR = "error"
    CANCELLED = "cancelled"
    WARNING = "warning"

class LogLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"

# Usage:
self.update_status(Status.READY)
self.log_message(..., level=LogLevel.INFO)
```

**Issue 8.2: Duplicated CSS Styles**

Similar styles are defined both in `DEFAULT_CSS` class attributes and in `main.tcss`.

**Example:**
- `/Users/ic/cptc11/python/tui/widgets/tool_panel.py` defines `ToolItem` styles
- `/Users/ic/cptc11/python/tui/styles/main.tcss` also defines `.tool-item` styles

**Recommended:** Choose one approach - either all styles in TCSS or all in `DEFAULT_CSS`, not both.

**Issue 8.3: Incomplete Error Messages**

Some error messages lack context for debugging.

**Location:** `/Users/ic/cptc11/python/tui/screens/tool_config.py` (line 259-262)

**Current Code:**
```python
if missing_required:
    self.notify(
        f"Missing required fields: {', '.join(missing_required)}",
        severity="error"
    )
```

**Recommended Fix:**
```python
if missing_required:
    self.notify(
        f"Cannot run {self.tool.name}: missing required fields: {', '.join(missing_required)}",
        severity="error",
        timeout=5
    )
```

---

## Recommendations Summary

### High Priority (Must Fix)

1. **Fix import error in `widgets/__init__.py`** - Currently broken due to `StatusBar` vs `ToolsmithStatusBar` naming
2. **Add proper error handling** to `parse_port_range` and other utility functions
3. **Replace `asyncio.create_task`** with Textual's worker system
4. **Add query_one error handling** to prevent runtime crashes

### Medium Priority (Should Fix)

5. Move `DashboardScreen` to `screens/dashboard.py` properly
6. Implement dependency injection for testability
7. Add event pruning in `AttackVisualizer` to prevent memory issues
8. Convert magic strings to Enums
9. Cache computed values like `_tools_by_category`

### Low Priority (Nice to Have)

10. Consolidate CSS to single location (either DEFAULT_CSS or TCSS)
11. Improve documentation for planned vs implemented features
12. Add comprehensive logging throughout the application
13. Create protocol classes for better abstraction

---

## Test Coverage Recommendations

Based on this review, the following test suites should be prioritized:

1. **Unit Tests for utils/helpers.py** - All pure functions should have comprehensive tests
2. **Widget Integration Tests** - Test `ToolPanel`, `OutputViewer`, `StatusBar` in isolation
3. **Screen Tests** - Test `ToolConfigScreen` validation logic
4. **Message Flow Tests** - Verify message passing between components
5. **Edge Case Tests** - Empty inputs, boundary values, error conditions

---

## Conclusion

The TUI codebase demonstrates solid Textual framework knowledge and Python best practices. The main areas for improvement are error handling robustness, testability through dependency injection, and fixing the identified import issues. With the recommended changes, this codebase would be well-positioned for production use and long-term maintenance.

**Files Reviewed:**
- `/Users/ic/cptc11/python/tui/app.py`
- `/Users/ic/cptc11/python/tui/__init__.py`
- `/Users/ic/cptc11/python/tui/__main__.py`
- `/Users/ic/cptc11/python/tui/screens/dashboard.py`
- `/Users/ic/cptc11/python/tui/screens/tool_config.py`
- `/Users/ic/cptc11/python/tui/screens/__init__.py`
- `/Users/ic/cptc11/python/tui/widgets/tool_panel.py`
- `/Users/ic/cptc11/python/tui/widgets/output_viewer.py`
- `/Users/ic/cptc11/python/tui/widgets/status_bar.py`
- `/Users/ic/cptc11/python/tui/widgets/__init__.py`
- `/Users/ic/cptc11/python/tui/visualizers/attack_visualizer.py`
- `/Users/ic/cptc11/python/tui/visualizers/__init__.py`
- `/Users/ic/cptc11/python/tui/styles/main.tcss`
- `/Users/ic/cptc11/python/tui/utils/helpers.py`
- `/Users/ic/cptc11/python/tui/utils/__init__.py`
- `/Users/ic/cptc11/python/tui/components/__init__.py`
