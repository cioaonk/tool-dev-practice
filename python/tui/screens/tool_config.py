"""
Tool Configuration Screen

A modal screen for configuring tool parameters before execution.
Supports Docker target integration for quick-select options.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Dict, Any, Optional, List, Callable

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.containers import Vertical, Horizontal, Container, ScrollableContainer
from textual.widgets import Static, Button, Input, Label, Select, OptionList
from textual.widgets.option_list import Option
from textual.binding import Binding
from textual.message import Message

from ..utils.docker_targets import DockerTargetManager, DockerTarget, get_docker_target_manager

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

    def set_value(self, value: str) -> None:
        """Set the input value."""
        input_widget = self.query_one(f"#input-{self.param_name}", Input)
        input_widget.value = value


class DockerTargetSelector(Vertical):
    """Widget for selecting Docker containers as targets."""

    DEFAULT_CSS = """
    DockerTargetSelector {
        height: auto;
        max-height: 15;
        border: round $secondary;
        background: $surface-darken-1;
        padding: 1;
        margin: 1 0;
    }

    DockerTargetSelector #docker-target-title {
        text-style: bold;
        color: $warning;
        padding-bottom: 1;
    }

    DockerTargetSelector #docker-target-list {
        height: auto;
        max-height: 10;
        scrollbar-background: $surface;
        scrollbar-color: $warning;
    }

    DockerTargetSelector .target-option {
        padding: 0 1;
        height: 2;
    }

    DockerTargetSelector .target-option:hover {
        background: $warning-darken-2;
    }

    DockerTargetSelector .target-option:focus {
        background: $warning-darken-1;
    }

    DockerTargetSelector #no-targets {
        color: $text-muted;
        text-style: italic;
        padding: 1;
    }

    DockerTargetSelector #scan-all-btn {
        margin-top: 1;
        background: $warning;
    }

    DockerTargetSelector #loading-targets {
        color: $text-muted;
        text-style: italic;
    }
    """

    class TargetSelected(Message):
        """Message sent when a Docker target is selected."""

        def __init__(self, target_ip: str, target_port: str, target_name: str) -> None:
            self.target_ip = target_ip
            self.target_port = target_port
            self.target_name = target_name
            super().__init__()

    class ScanAllSelected(Message):
        """Message sent when 'Scan All' is selected."""

        def __init__(self, subnet: str, targets: List[str]) -> None:
            self.subnet = subnet
            self.targets = targets
            super().__init__()

    def __init__(
        self,
        show_scan_all: bool = True,
        filter_services: Optional[List[str]] = None,
        *args,
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.show_scan_all = show_scan_all
        self.filter_services = filter_services
        self._targets: List[DockerTarget] = []
        self._manager = get_docker_target_manager()

    def compose(self) -> ComposeResult:
        """Compose the target selector."""
        yield Static("[b]Docker Targets[/b]", id="docker-target-title")
        yield Static("[dim]Loading targets...[/dim]", id="loading-targets")

        with ScrollableContainer(id="docker-target-list"):
            pass  # Will be populated async

        if self.show_scan_all:
            yield Button("Scan Docker Environment", id="scan-all-btn")

    async def on_mount(self) -> None:
        """Load Docker targets on mount."""
        await self._load_targets()

    async def _load_targets(self) -> None:
        """Load available Docker targets."""
        try:
            self._targets = await self._manager.get_running_targets()
        except Exception:
            self._targets = []

        # Remove loading indicator
        try:
            loading = self.query_one("#loading-targets", Static)
            loading.remove()
        except Exception:
            pass

        # Populate target list
        target_list = self.query_one("#docker-target-list", ScrollableContainer)

        if not self._targets:
            await target_list.mount(
                Static("[dim]No running Docker targets[/dim]", id="no-targets")
            )
            return

        for target in self._targets:
            if not target.primary_ip:
                continue

            # Add main target option
            target_widget = Static(
                f"[b]{target.display_name}[/b] ({target.primary_ip})",
                classes="target-option",
                id=f"target-{target.container_id}"
            )
            target_widget.can_focus = True
            await target_list.mount(target_widget)

            # Add service-specific options
            for service in target.services:
                if self.filter_services and service.name.lower() not in [
                    s.lower() for s in self.filter_services
                ]:
                    continue

                host_port = target.ports.get(service.port, service.port)
                service_widget = Static(
                    f"  [cyan]{service.name}[/cyan] - {target.primary_ip}:{host_port}",
                    classes="target-option",
                    id=f"service-{target.container_id}-{service.port}"
                )
                service_widget.can_focus = True
                await target_list.mount(service_widget)

    def on_static_focus(self, event) -> None:
        """Handle target selection via focus."""
        widget_id = event.widget.id
        if not widget_id:
            return

        if widget_id.startswith("target-"):
            container_id = widget_id.replace("target-", "")
            for target in self._targets:
                if target.container_id == container_id:
                    self.post_message(
                        self.TargetSelected(
                            target_ip=target.primary_ip or "",
                            target_port="",
                            target_name=target.display_name
                        )
                    )
                    break

        elif widget_id.startswith("service-"):
            parts = widget_id.replace("service-", "").split("-")
            if len(parts) >= 2:
                container_id = parts[0]
                port = int(parts[1])
                for target in self._targets:
                    if target.container_id == container_id:
                        host_port = target.ports.get(port, port)
                        service_name = ""
                        for s in target.services:
                            if s.port == port:
                                service_name = s.name
                                break
                        self.post_message(
                            self.TargetSelected(
                                target_ip=target.primary_ip or "",
                                target_port=str(host_port),
                                target_name=f"{target.display_name} - {service_name}"
                            )
                        )
                        break

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle scan all button."""
        if event.button.id == "scan-all-btn":
            preset = await self._manager.get_scan_all_preset()
            if preset.get("subnets"):
                self.post_message(
                    self.ScanAllSelected(
                        subnet=preset["subnets"][0],
                        targets=preset.get("targets", [])
                    )
                )


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

    ToolConfigScreen #docker-targets-section {
        border-top: solid $warning;
        margin-top: 1;
        padding-top: 1;
    }

    ToolConfigScreen #prefill-notice {
        color: $success;
        text-style: italic;
        padding: 1 0;
        text-align: center;
    }

    ToolConfigScreen #target-info-box {
        color: $success;
        text-align: center;
        padding: 0 1;
        border: round $success;
        margin-bottom: 1;
        height: auto;
    }
    """

    # Tools that support target selection
    TARGET_TOOLS = {"Port Scanner", "Network Mapper", "Vuln Scanner", "Attack Simulator"}
    SUBNET_TOOLS = {"Network Mapper"}

    def __init__(
        self,
        tool: "SecurityTool",
        prefill_target: Optional[Dict[str, str]] = None,
        target_info: Optional[str] = None,
        *args,
        **kwargs
    ) -> None:
        """
        Initialize the tool configuration screen.

        Args:
            tool: The SecurityTool to configure
            prefill_target: Optional dictionary of parameter names to values
                           to pre-populate in the form
            target_info: Optional string describing the target (e.g., node name)
        """
        super().__init__(*args, **kwargs)
        self.tool = tool
        self.prefill_target = prefill_target or {}
        self.target_info = target_info
        self._param_inputs: Dict[str, ParameterInput] = {}
        self._show_docker_targets = tool.name in self.TARGET_TOOLS

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

            # Show target info if provided
            if self.target_info:
                yield Static(
                    f"[b]Target:[/b] {self.target_info}",
                    id="target-info-box"
                )

            with ScrollableContainer(id="params-container"):
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

                # Docker target selector for supported tools
                if self._show_docker_targets:
                    with Vertical(id="docker-targets-section"):
                        show_scan_all = self.tool.name in self.SUBNET_TOOLS
                        yield DockerTargetSelector(
                            show_scan_all=show_scan_all,
                            id="docker-target-selector"
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

    def on_mount(self) -> None:
        """Apply prefill values after mount."""
        if self.prefill_target:
            for param_name, value in self.prefill_target.items():
                if param_name in self._param_inputs:
                    self._param_inputs[param_name].set_value(value)

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

    def on_docker_target_selector_target_selected(
        self,
        message: DockerTargetSelector.TargetSelected
    ) -> None:
        """Handle Docker target selection - auto-fill target fields."""
        # Find and fill target-related parameters
        for param_name, param_input in self._param_inputs.items():
            name_lower = param_name.lower()

            if name_lower in ("target", "host", "ip"):
                # Fill with IP:port if port available, otherwise just IP
                if message.target_port:
                    param_input.set_value(f"{message.target_ip}:{message.target_port}")
                else:
                    param_input.set_value(message.target_ip)

            elif name_lower == "ports" and message.target_port:
                param_input.set_value(message.target_port)

        self.notify(
            f"Target set: {message.target_name}",
            severity="information"
        )

    def on_docker_target_selector_scan_all_selected(
        self,
        message: DockerTargetSelector.ScanAllSelected
    ) -> None:
        """Handle 'Scan All' selection - fill subnet parameter."""
        for param_name, param_input in self._param_inputs.items():
            name_lower = param_name.lower()

            if name_lower == "subnet":
                param_input.set_value(message.subnet)
            elif name_lower in ("target", "host", "ip"):
                # For target-based tools, join all IPs
                param_input.set_value(",".join(message.targets))

        self.notify(
            f"Scanning Docker environment: {message.subnet}",
            severity="information"
        )
