"""
Tool Panel Widget

A sidebar panel that displays available security tools organized by category.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Dict, Optional, Any
from dataclasses import dataclass

from textual.app import ComposeResult
from textual.containers import Vertical, ScrollableContainer
from textual.widgets import Static, Label, Button, ListItem, ListView
from textual.widget import Widget
from textual.message import Message
from textual.reactive import reactive
from textual.binding import Binding

if TYPE_CHECKING:
    from ..app import SecurityTool


class ToolItem(Static):
    """A clickable tool item in the tool list."""

    BINDINGS = [
        Binding("enter", "select", "Select Tool", show=False),
    ]

    DEFAULT_CSS = """
    ToolItem {
        height: 3;
        padding: 0 1;
        margin-bottom: 1;
        border: round $secondary;
        background: $surface;
    }

    ToolItem:hover {
        background: $primary-darken-1;
    }

    ToolItem:focus {
        background: $primary;
        border: round $accent;
    }

    ToolItem.--selected {
        background: $primary;
        border: double $accent;
    }

    ToolItem .tool-name {
        text-style: bold;
        color: $text;
    }

    ToolItem .tool-category {
        color: $text-muted;
        text-style: italic;
    }
    """

    class Selected(Message):
        """Message sent when a tool is selected."""

        def __init__(self, tool: "SecurityTool") -> None:
            self.tool = tool
            super().__init__()

    def __init__(
        self,
        tool: "SecurityTool",
        *args,
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.tool = tool
        self.can_focus = True

    def compose(self) -> ComposeResult:
        """Compose the tool item display."""
        yield Static(f"[b]{self.tool.name}[/b]", classes="tool-name")
        yield Static(f"[i]{self.tool.category}[/i]", classes="tool-category")

    def on_click(self) -> None:
        """Handle click events."""
        self.action_select()

    def action_select(self) -> None:
        """Select this tool."""
        self.add_class("--selected")
        self.post_message(self.Selected(self.tool))

    def deselect(self) -> None:
        """Deselect this tool."""
        self.remove_class("--selected")


class CategoryHeader(Static):
    """A category header in the tool list."""

    DEFAULT_CSS = """
    CategoryHeader {
        height: 2;
        padding: 0 1;
        margin-top: 1;
        background: $primary-darken-2;
        color: $primary-lighten-2;
        text-style: bold;
        border-bottom: solid $primary;
    }
    """

    def __init__(self, category: str, *args, **kwargs) -> None:
        super().__init__(f">> {category.upper()}", *args, **kwargs)


class ToolPanel(Widget):
    """
    Tool selection panel widget.

    Displays available security tools organized by category.
    Allows users to browse and select tools for execution.
    """

    DEFAULT_CSS = """
    ToolPanel {
        width: 100%;
        height: 100%;
        border: solid $primary;
        background: $surface-darken-1;
        padding: 1;
    }

    ToolPanel #tool-panel-title {
        text-style: bold;
        color: $primary;
        text-align: center;
        padding-bottom: 1;
        border-bottom: solid $secondary;
        margin-bottom: 1;
    }

    ToolPanel #tool-list-container {
        height: 100%;
        scrollbar-background: $surface;
        scrollbar-color: $primary;
    }

    ToolPanel #tool-count {
        dock: bottom;
        height: 1;
        text-align: center;
        color: $text-muted;
        padding-top: 1;
        border-top: solid $secondary;
    }
    """

    class ToolSelected(Message):
        """Message sent when a tool is selected from the panel."""

        def __init__(self, tool: "SecurityTool") -> None:
            self.tool = tool
            super().__init__()

    # Reactive attributes
    selected_tool: reactive[Optional["SecurityTool"]] = reactive(None)
    filter_category: reactive[Optional[str]] = reactive(None)

    def __init__(
        self,
        tools: List["SecurityTool"],
        *args,
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.tools = tools
        self._tool_items: Dict[str, ToolItem] = {}

    def compose(self) -> ComposeResult:
        """Compose the tool panel layout."""
        yield Label("[b]SECURITY TOOLS[/b]", id="tool-panel-title")

        with ScrollableContainer(id="tool-list-container"):
            # Group tools by category
            categories: Dict[str, List["SecurityTool"]] = {}
            for tool in self.tools:
                if tool.category not in categories:
                    categories[tool.category] = []
                categories[tool.category].append(tool)

            # Render tools by category
            for category in sorted(categories.keys()):
                yield CategoryHeader(category)
                for tool in categories[category]:
                    item = ToolItem(tool, id=f"tool-{tool.name.lower().replace(' ', '-')}")
                    self._tool_items[tool.name] = item
                    yield item

        yield Static(f"{len(self.tools)} tools available", id="tool-count")

    def on_tool_item_selected(self, message: ToolItem.Selected) -> None:
        """Handle tool item selection."""
        # Deselect all other items
        for item in self._tool_items.values():
            if item.tool != message.tool:
                item.deselect()

        # Update selected tool
        self.selected_tool = message.tool

        # Bubble up the selection
        self.post_message(self.ToolSelected(message.tool))

    def watch_filter_category(self, category: Optional[str]) -> None:
        """React to category filter changes."""
        for tool_name, item in self._tool_items.items():
            if category is None:
                item.display = True
            else:
                item.display = item.tool.category == category

    def get_tool_by_name(self, name: str) -> Optional["SecurityTool"]:
        """Get a tool by its name."""
        for tool in self.tools:
            if tool.name == name:
                return tool
        return None

    def filter_by_category(self, category: Optional[str]) -> None:
        """Filter tools by category."""
        self.filter_category = category

    def reset_filter(self) -> None:
        """Reset the category filter."""
        self.filter_category = None
