"""
Tool Configuration Screen

A modal screen for configuring tool parameters before execution.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Any, Optional, List

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.containers import Vertical, Horizontal, Container
from textual.widgets import Static, Button, Input, Label
from textual.binding import Binding
from textual.message import Message

if TYPE_CHECKING:
    from ..app import SecurityTool


class ParameterInput(Vertical):
    """A parameter input field with label."""

    DEFAULT_CSS = """
    ParameterInput {
        height: auto;
        margin: 1 0;
        padding: 0;
    }

    ParameterInput .param-label {
        color: $text;
        padding: 0;
        margin-bottom: 0;
    }

    ParameterInput .param-required {
        color: $error;
    }

    ParameterInput .param-description {
        color: $text-muted;
        text-style: italic;
        padding: 0;
    }

    ParameterInput Input {
        margin-top: 0;
        border: round $secondary;
        background: $surface-darken-1;
    }

    ParameterInput Input:focus {
        border: round $primary;
    }
    """

    def __init__(
        self,
        param_name: str,
        param_type: str,
        required: bool,
        description: str,
        default: str = "",
        *args,
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.param_name = param_name
        self.param_type = param_type
        self.required = required
        self.description = description
        self.default = default

    def compose(self) -> ComposeResult:
        """Compose the parameter input."""
        required_marker = "[red]*[/red] " if self.required else ""
        yield Static(
            f"{required_marker}[b]{self.param_name}[/b] ({self.param_type})",
            classes="param-label"
        )
        yield Static(self.description, classes="param-description")
        yield Input(
            value=self.default,
            placeholder=f"Enter {self.param_name}...",
            id=f"input-{self.param_name}"
        )

    def get_value(self) -> str:
        """Get the current input value."""
        input_widget = self.query_one(f"#input-{self.param_name}", Input)
        return input_widget.value


class ToolConfigScreen(ModalScreen[Optional[Dict[str, str]]]):
    """
    Modal screen for configuring tool parameters.

    Returns a dictionary of parameter values when confirmed,
    or None if cancelled.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("enter", "confirm", "Confirm", show=False),
    ]

    DEFAULT_CSS = """
    ToolConfigScreen {
        align: center middle;
        background: $surface 60%;
    }

    ToolConfigScreen #config-container {
        width: 70;
        height: auto;
        max-height: 90%;
        background: $surface;
        border: double $primary;
        padding: 1 2;
    }

    ToolConfigScreen #config-title {
        text-style: bold;
        color: $primary;
        text-align: center;
        padding: 1 0;
        border-bottom: solid $secondary;
        margin-bottom: 1;
    }

    ToolConfigScreen #tool-description {
        color: $text-muted;
        text-style: italic;
        padding: 0 0 1 0;
        text-align: center;
    }

    ToolConfigScreen #params-container {
        height: auto;
        max-height: 60%;
        padding: 1 0;
    }

    ToolConfigScreen #button-container {
        layout: horizontal;
        align: center middle;
        padding-top: 1;
        border-top: solid $secondary;
        margin-top: 1;
        height: 4;
    }

    ToolConfigScreen .config-button {
        margin: 0 1;
        min-width: 14;
    }

    ToolConfigScreen #confirm-btn {
        background: $success;
    }

    ToolConfigScreen #confirm-btn:hover {
        background: $success-lighten-1;
    }

    ToolConfigScreen #cancel-btn {
        background: $error;
    }

    ToolConfigScreen #cancel-btn:hover {
        background: $error-lighten-1;
    }

    ToolConfigScreen #required-note {
        color: $text-muted;
        text-align: center;
        padding: 1 0 0 0;
    }
    """

    def __init__(self, tool: "SecurityTool", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.tool = tool
        self._param_inputs: Dict[str, ParameterInput] = {}

    def compose(self) -> ComposeResult:
        """Compose the configuration screen."""
        with Container(id="config-container"):
            yield Static(
                f"[b]Configure: {self.tool.name}[/b]",
                id="config-title"
            )
            yield Static(
                self.tool.description,
                id="tool-description"
            )

            with Vertical(id="params-container"):
                # Create input fields for each parameter
                for param in self.tool.parameters:
                    param_input = ParameterInput(
                        param_name=param["name"],
                        param_type=param.get("type", "str"),
                        required=param.get("required", False),
                        description=param.get("description", ""),
                        default=param.get("default", ""),
                        id=f"param-{param['name']}"
                    )
                    self._param_inputs[param["name"]] = param_input
                    yield param_input

                # Note about required fields
                has_required = any(p.get("required") for p in self.tool.parameters)
                if has_required:
                    yield Static(
                        "[red]*[/red] Required fields",
                        id="required-note"
                    )

            with Horizontal(id="button-container"):
                yield Button(
                    "Cancel",
                    variant="error",
                    id="cancel-btn",
                    classes="config-button"
                )
                yield Button(
                    "Run Tool",
                    variant="success",
                    id="confirm-btn",
                    classes="config-button"
                )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "confirm-btn":
            self.action_confirm()
        elif event.button.id == "cancel-btn":
            self.action_cancel()

    def action_confirm(self) -> None:
        """Confirm and return parameters."""
        # Validate required fields
        params: Dict[str, str] = {}
        missing_required: List[str] = []

        for param in self.tool.parameters:
            name = param["name"]
            value = self._param_inputs[name].get_value()
            params[name] = value

            if param.get("required") and not value.strip():
                missing_required.append(name)

        if missing_required:
            # Show error - for now just notify via the app
            self.notify(
                f"Missing required fields: {', '.join(missing_required)}",
                severity="error"
            )
            return

        self.dismiss(params)

    def action_cancel(self) -> None:
        """Cancel and return None."""
        self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in input fields."""
        # Move to next input or confirm
        inputs = list(self.query(Input))
        current_index = -1

        for i, inp in enumerate(inputs):
            if inp.id == event.input.id:
                current_index = i
                break

        if current_index >= 0 and current_index < len(inputs) - 1:
            # Focus next input
            inputs[current_index + 1].focus()
        else:
            # Last input - confirm
            self.action_confirm()
