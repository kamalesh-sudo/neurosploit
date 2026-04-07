from __future__ import annotations

from collections import deque
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from rich import box
from rich.syntax import Syntax
from rich.table import Table
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.message import Message
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.widgets import (
    Button,
    DataTable,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)
try:
    # Textual >= 0.60 / modern releases expose work at package root.
    from textual import work
except ImportError:  # pragma: no cover - compatibility fallback
    from textual.work import work  # type: ignore

from .core import ScanConfig, export_report, run_enhanced_recon_async
from .targets import is_valid_domain, normalize_domain


def _hex_to_rgb(color: str) -> tuple[int, int, int]:
    color = color.strip().lstrip("#")
    return int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)


def _rgb_to_hex(rgb: tuple[int, int, int]) -> str:
    r, g, b = rgb
    return f"#{r:02x}{g:02x}{b:02x}"


def _lerp_color(start: str, end: str, t: float) -> str:
    t = max(0.0, min(1.0, t))
    sr, sg, sb = _hex_to_rgb(start)
    er, eg, eb = _hex_to_rgb(end)
    rgb = (
        int(sr + (er - sr) * t),
        int(sg + (eg - sg) * t),
        int(sb + (eb - sb) * t),
    )
    return _rgb_to_hex(rgb)


def gradient_text(text: str, start: str = "#47e5ff", end: str = "#ff5fd2") -> str:
    if not text:
        return ""
    chars: List[str] = []
    span = max(1, len(text) - 1)
    for idx, char in enumerate(text):
        color = _lerp_color(start, end, idx / span)
        if char == " ":
            chars.append(" ")
        else:
            chars.append(f"[{color}]{char}[/]")
    return "".join(chars)


def gradient_bar(ratio: float, width: int = 34, start: str = "#47e5ff", end: str = "#ff5fd2") -> str:
    ratio = max(0.0, min(1.0, ratio))
    filled = int(round(width * ratio))
    cells: List[str] = []
    span = max(1, width - 1)
    for i in range(width):
        color = _lerp_color(start, end, i / span)
        char = "█" if i < filled else "░"
        cells.append(f"[{color}]{char}[/]")
    return "".join(cells)


def _resample(values: List[float], count: int) -> List[float]:
    if count <= 0:
        return []
    if not values:
        return [0.0] * count
    if len(values) == count:
        return values
    if len(values) < count:
        padded = values[:]
        padded.extend([values[-1]] * (count - len(values)))
        return padded

    sampled: List[float] = []
    step = len(values) / count
    for i in range(count):
        start = int(i * step)
        end = int((i + 1) * step)
        if end <= start:
            end = start + 1
        bucket = values[start:end]
        sampled.append(sum(bucket) / len(bucket))
    return sampled


def braille_sparkline(values: List[float], width: int = 36) -> str:
    width = max(2, width)
    samples = _resample(values, width * 2)

    if not samples:
        return "⠀" * width

    min_v = min(samples)
    max_v = max(samples)
    span = max(max_v - min_v, 1e-9)

    left_bits = [0x40, 0x04, 0x02, 0x01]   # bottom -> top
    right_bits = [0x80, 0x20, 0x10, 0x08]  # bottom -> top

    chars: List[str] = []
    for i in range(0, len(samples), 2):
        left = int(round(((samples[i] - min_v) / span) * 4))
        right = int(round(((samples[i + 1] - min_v) / span) * 4)) if i + 1 < len(samples) else 0

        code = 0x2800
        for bit in left_bits[: max(0, min(4, left))]:
            code += bit
        for bit in right_bits[: max(0, min(4, right))]:
            code += bit

        chars.append(chr(code))
    return "".join(chars)


def block_sparkline(values: List[float], width: int = 18) -> str:
    ticks = "▁▂▃▄▅▆▇█"
    sampled = _resample(values, max(2, width))
    if not sampled:
        return "▁" * width
    low = min(sampled)
    high = max(sampled)
    span = max(high - low, 1e-9)
    chars: List[str] = []
    for value in sampled:
        idx = int(round(((value - low) / span) * (len(ticks) - 1)))
        chars.append(ticks[max(0, min(len(ticks) - 1, idx))])
    return "".join(chars)


class ScanLog(Message):
    def __init__(self, target: str, text: str) -> None:
        super().__init__()
        self.target = target
        self.text = text


class ScanProgress(Message):
    def __init__(self, target: str, phase: str, current: int, total: int, text: str) -> None:
        super().__init__()
        self.target = target
        self.phase = phase
        self.current = current
        self.total = total
        self.text = text


class ScanFinished(Message):
    def __init__(self, target: str, report: Optional[Dict[str, Any]], error: Optional[str]) -> None:
        super().__init__()
        self.target = target
        self.report = report
        self.error = error


class AddTargetModal(ModalScreen[Optional[str]]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Container(classes="target-modal"):
            yield Static("Add Target", classes="modal-title")
            yield Input(placeholder="example.com", id="target-input")
            with Horizontal(classes="modal-actions"):
                yield Button("Add", variant="success", id="target-save")
                yield Button("Cancel", id="target-cancel")

    def on_mount(self) -> None:
        self.query_one("#target-input", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "target-save":
            value = normalize_domain(self.query_one("#target-input", Input).value)
            self.dismiss(value if value else None)
            return
        self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = normalize_domain(event.value)
        self.dismiss(value if value else None)


class SettingsOverlay(ModalScreen[Optional[Dict[str, str]]]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, current_theme: str, current_intensity: str) -> None:
        super().__init__()
        self.selected_theme = current_theme
        self.selected_intensity = current_intensity

    def compose(self) -> ComposeResult:
        with Container(classes="settings-modal"):
            yield Static("Settings", classes="modal-title")
            with TabbedContent(id="settings-tabs"):
                with TabPane("Theme", id="theme-tab"):
                    yield Static("Switch color profile", classes="overlay-hint")
                    with Horizontal(classes="choice-row"):
                        yield Button("Monokai", id="theme-monokai", classes="settings-option")
                        yield Button("Dracula", id="theme-dracula", classes="settings-option")
                with TabPane("Scan Intensity", id="intensity-tab"):
                    yield Static("Adjust scan pressure", classes="overlay-hint")
                    with Horizontal(classes="choice-row"):
                        yield Button("Low", id="intensity-low", classes="settings-option")
                        yield Button("Medium", id="intensity-medium", classes="settings-option")
                        yield Button("High", id="intensity-high", classes="settings-option")
            with Horizontal(classes="modal-actions"):
                yield Button("Save", variant="success", id="settings-save")
                yield Button("Cancel", id="settings-cancel")

    def on_mount(self) -> None:
        self._sync_option_styles()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""

        if button_id == "settings-save":
            self.dismiss({"theme": self.selected_theme, "intensity": self.selected_intensity})
            return
        if button_id == "settings-cancel":
            self.dismiss(None)
            return
        if button_id.startswith("theme-"):
            self.selected_theme = button_id.split("-", 1)[1]
            self._sync_option_styles()
            return
        if button_id.startswith("intensity-"):
            self.selected_intensity = button_id.split("-", 1)[1]
            self._sync_option_styles()

    def _sync_option_styles(self) -> None:
        theme_buttons = ["theme-monokai", "theme-dracula"]
        intensity_buttons = ["intensity-low", "intensity-medium", "intensity-high"]

        for button_id in theme_buttons:
            button = self.query_one(f"#{button_id}", Button)
            button.set_class(button_id == f"theme-{self.selected_theme}", "is-selected")

        for button_id in intensity_buttons:
            button = self.query_one(f"#{button_id}", Button)
            button.set_class(button_id == f"intensity-{self.selected_intensity}", "is-selected")


class NeuroSploitTUI(App[None]):
    CSS_PATH = "tui.tcss"
    TITLE = "NeuroSploit"
    SUB_TITLE = "btop-style Recon Console"

    MIN_WIDTH = 110
    MIN_HEIGHT = 34

    INTENSITY_PRESETS: Dict[str, Dict[str, int]] = {
        "low": {"max_concurrency": 20, "timeout": 8},
        "medium": {"max_concurrency": 40, "timeout": 5},
        "high": {"max_concurrency": 80, "timeout": 3},
    }

    BINDINGS = [
        Binding("s", "run_selected_scan", "Scan"),
        Binding("a", "add_target", "Add"),
        Binding("t", "open_settings", "Settings"),
        Binding("c", "clear_logs", "Clear"),
        Binding("e", "export_selected", "Export"),
        Binding("slash", "focus_command", "Command"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.targets: List[str] = self._load_targets_from_file()
        self.scan_config = ScanConfig()
        self.scan_intensity = "medium"
        self.ui_theme = "monokai"

        self.reports: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.result_rows: List[Dict[str, Any]] = []

        self.sort_column = "status_code"
        self.sort_reverse = False

        self.ports_history: Deque[float] = deque([0.0] * 64, maxlen=160)
        self.latency_history: Deque[float] = deque([0.0] * 64, maxlen=160)
        self.progress_history: Deque[float] = deque([0.0] * 64, maxlen=160)
        self.layout_profile = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="app-shell"):
            with Container(id="dashboard"):
                with Container(id="brand-card", classes="card"):
                    yield Static("✦", id="brand-glyph")
                    yield Static("Puzzlebot", id="brand-name")
                    yield Static("NeuroSploit Console", id="brand-sub")

                with Container(id="actions-card", classes="card"):
                    yield Button("● Automatic assignment", id="btn-assign", classes="action-pill")
                    yield Button("● Help me categorize", id="btn-categorize", classes="action-pill")
                    yield Button("● AI categorizer", id="btn-ai", classes="action-pill")
                    with Horizontal(classes="panel-actions"):
                        yield Button("Add", id="btn-add", classes="panel-btn")
                        yield Button("Scan", id="btn-scan", classes="panel-btn")
                        yield Button("Settings", id="btn-settings", classes="panel-btn")

                with Container(id="stats-panel", classes="card panel"):
                    yield Static(id="stats-title", classes="panel-title")
                    yield Static(id="stats-body")
                    yield Static(id="finance-grid")
                    yield Static(id="ports-graph", classes="graph-line")
                    yield Static(id="latency-graph", classes="graph-line")

                with Container(id="targets-panel", classes="card panel"):
                    yield Static(id="targets-title", classes="panel-title")
                    yield Static(id="company-form")
                    yield ListView(*[ListItem(Label(target)) for target in self.targets], id="target-list")

                with Container(id="results-panel", classes="card panel"):
                    yield Static(id="results-title", classes="panel-title")
                    yield Static(id="results-graph", classes="graph-line")
                    yield DataTable(id="results-view", zebra_stripes=True)

                with Container(id="tasks-panel", classes="card panel"):
                    yield Static(id="tasks-title", classes="panel-title")
                    yield Static(id="team-tabs")
                    yield DataTable(id="task-view", zebra_stripes=True)

                with Container(id="compare-card", classes="card"):
                    yield Static(id="compare-title")
                    yield Static(id="compare-body")
                    yield Static(id="compare-graph", classes="graph-line")

                with Container(id="instant-card", classes="card"):
                    yield Static(id="instant-title")
                    yield Static(id="instant-body")

                with Container(id="logs-panel", classes="card panel"):
                    yield Static(id="logs-title", classes="panel-title")
                    yield Static(id="quote-blurb")
                    yield RichLog(id="log-view", highlight=True, markup=True, wrap=True)
                    with Horizontal(classes="panel-actions"):
                        yield Button("Clear Logs", id="btn-clear-logs", classes="panel-btn")

                with Container(id="export-card", classes="card"):
                    yield Static(id="export-title")
                    yield Static(id="export-body")
                    yield Button("Export recon package", id="btn-export", classes="panel-btn full-btn")

                with Container(id="revenue-card", classes="card"):
                    yield Static(id="revenue-title")
                    yield Static(id="revenue-graph", classes="graph-line")

            with Horizontal(id="command-row"):
                yield Input(placeholder=":help for commands", id="command-input")

            yield Static(id="hotkey-bar")
            yield Static(id="status-bar")

        with Container(id="too-small-overlay"):
            with Container(id="too-small-box"):
                yield Static("TERMINAL TOO SMALL", id="too-small-title")
                yield Static(
                    "Resize to at least 110x34 for the full btop-style dashboard.",
                    id="too-small-text",
                )

    def on_mount(self) -> None:
        self._init_tables()
        self._apply_theme(self.ui_theme)
        self._render_titles()
        self._render_dashboard_chrome()
        self._render_hotkeys()
        self._refresh_stats_panel()
        self._apply_layout_profile(self.size.width, self.size.height)
        self._update_size_warning(self.size.width, self.size.height)

        if self.targets:
            self.query_one("#target-list", ListView).index = 0

        self.set_interval(0.5, self._refresh_stats_panel)
        self._set_status("Ready. [S]can selected target or [A]dd new domain.")
        self._log("system", "[bold #89ffb5]NeuroSploit btop UI online[/]")

    def _init_tables(self) -> None:
        results = self.query_one("#results-view", DataTable)
        results.add_column("Target", key="target")
        results.add_column("Subdomain", key="subdomain")
        results.add_column("IP", key="ip")
        results.add_column("Status", key="status_code")
        results.add_column("Proto", key="protocol")
        results.add_column("Server", key="server")
        results.add_column("Tech", key="technology")
        results.add_column("Ports", key="ports")
        results.cursor_type = "row"

        tasks = self.query_one("#task-view", DataTable)
        tasks.add_column("Target", key="target")
        tasks.add_column("Phase", key="phase")
        tasks.add_column("Progress", key="progress")
        tasks.add_column("Status", key="status")

    def _render_titles(self) -> None:
        self.query_one("#targets-title", Static).update(gradient_text("╭ About Your Company ╮"))
        self.query_one("#stats-title", Static).update(gradient_text("╭ April Financial Highlights ╮"))
        self.query_one("#tasks-title", Static).update(gradient_text("╭ Team Activity ╮"))
        self.query_one("#results-title", Static).update(gradient_text("╭ Scan Timeline & Subdomains ╮"))
        self.query_one("#logs-title", Static).update(gradient_text("╭ Live Log ╮"))

    def _render_dashboard_chrome(self) -> None:
        self.query_one("#team-tabs", Static).update(
            "[on #20264d][#9ea6cc]  All Team Members  [/]   "
            "[on #363b73][bold #f6e96b]  Accounting/Finance  [/]   "
            "[on #20264d][#9ea6cc]  Tech  [/]"
        )
        self.query_one("#compare-title", Static).update(gradient_text("ARR"))
        self.query_one("#compare-body", Static).update(
            "[#9ea6cc]With Puzzle[/] [bold #5fffb4](4 steps)[/]      "
            "[#9ea6cc]Without Puzzle[/] [bold #8f8fb3](17 steps)[/]"
        )
        self.query_one("#instant-title", Static).update(gradient_text("Instant Metrics"))
        self.query_one("#export-title", Static).update(gradient_text("Export Settings"))
        self.query_one("#export-body", Static).update(
            "[#9ea6cc]Format:[/]  [#d8dcff].CSV[/]\n"
            "[#9ea6cc]Year:[/]    [#d8dcff]2026[/]\n"
            "[#9ea6cc]Basis:[/]   [#d8dcff]Accrual[/]"
        )
        self.query_one("#revenue-title", Static).update(gradient_text("Revenue"))
        self.query_one("#quote-blurb", Static).update(
            "\"Now I am able to look at a single dashboard for everything financial I need to improve my startup.\""
        )

    def _render_hotkeys(self) -> None:
        entries = [
            ("S", "can"),
            ("A", "dd"),
            ("T", "heme/Settings"),
            ("C", "lear"),
            ("E", "xport"),
            ("Q", "uit"),
            ("/", "Command"),
        ]
        # Keep markup simple to avoid nested bracket parsing issues.
        chunks = [f"[bold #f8f8f2][#66d9ef]{key}[/]{tail}[/]" for key, tail in entries]
        self.query_one("#hotkey-bar", Static).update("  ".join(chunks))

    def _targets_file_path(self) -> Path:
        return Path(__file__).resolve().parent / "data" / "urls.txt"

    def _load_targets_from_file(self) -> List[str]:
        file_path = self._targets_file_path()
        if not file_path.exists():
            return []

        raw_lines = [line.strip() for line in file_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        cleaned: List[str] = []
        for raw in raw_lines:
            normalized = normalize_domain(raw)
            if is_valid_domain(normalized):
                cleaned.append(normalized)

        deduped = list(dict.fromkeys(cleaned))
        if deduped != raw_lines:
            self._save_targets_to_file(deduped)
        return deduped

    def _save_targets_to_file(self, targets: Optional[List[str]] = None) -> None:
        file_path = self._targets_file_path()
        file_path.parent.mkdir(parents=True, exist_ok=True)
        data = targets if targets is not None else self.targets
        file_path.write_text("\n".join(data) + ("\n" if data else ""), encoding="utf-8")

    def _selected_target(self) -> Optional[str]:
        target_list = self.query_one("#target-list", ListView)
        if target_list.index is None:
            return None
        if target_list.index < 0 or target_list.index >= len(self.targets):
            return None
        return self.targets[target_list.index]

    def _add_target(self, target: str) -> bool:
        candidate = normalize_domain(target)
        if not candidate or not is_valid_domain(candidate):
            self._set_status(f"Invalid target: {target}")
            return False
        if candidate in self.targets:
            self._set_status(f"Target already exists: {candidate}")
            return False

        self.targets.append(candidate)
        self._save_targets_to_file()
        self.query_one("#target-list", ListView).append(ListItem(Label(candidate)))
        if len(self.targets) == 1:
            self.query_one("#target-list", ListView).index = 0
        self._set_status(f"Added target: {candidate}")
        return True

    def _set_status(self, text: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.query_one("#status-bar", Static).update(f"[{stamp}] {text}")

    def _log(self, source: str, text: str) -> None:
        self.query_one("#log-view", RichLog).write(f"[#66d9ef]{source:<10}[/] {text}")

    def _log_json(self, source: str, payload: Dict[str, Any]) -> None:
        syntax = Syntax(json.dumps(payload, indent=2, default=str), "json", word_wrap=True)
        log = self.query_one("#log-view", RichLog)
        log.write(f"[#66d9ef]{source:<10}[/] [bold #a6e22e]summary[/]")
        log.write(syntax)

    def _flatten_results(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for target, report in self.reports.items():
            for sub in report.get("live_subdomains", []):
                rows.append(
                    {
                        "target": target,
                        "subdomain": sub.get("subdomain", "-"),
                        "ip": sub.get("ip", "-"),
                        "status_code": int(sub.get("status_code", 0) or 0),
                        "protocol": sub.get("protocol", "-"),
                        "server": sub.get("server", "-"),
                        "technology": ", ".join(sub.get("technology", [])[:3]) if sub.get("technology") else "-",
                        "ports": ", ".join(str(p) for p in sub.get("open_ports", [])) if sub.get("open_ports") else "-",
                    }
                )

        if self.sort_column:
            rows.sort(key=lambda row: row.get(self.sort_column, ""), reverse=self.sort_reverse)
        return rows

    def _refresh_results_table(self) -> None:
        self.result_rows = self._flatten_results()
        table = self.query_one("#results-view", DataTable)
        table.clear(columns=False)
        for row in self.result_rows:
            table.add_row(
                row["target"],
                row["subdomain"],
                row["ip"],
                str(row["status_code"]),
                row["protocol"],
                row["server"],
                row["technology"],
                row["ports"],
            )

    def _refresh_tasks_table(self) -> None:
        table = self.query_one("#task-view", DataTable)
        table.clear(columns=False)
        for target, state in sorted(self.tasks.items()):
            total = int(state.get("total", 0))
            current = int(state.get("current", 0))
            if total > 0:
                progress = f"{int((current / total) * 100):>3}% ({current}/{total})"
            else:
                progress = str(state.get("text", "-"))
            table.add_row(
                target,
                str(state.get("phase", "-")),
                progress,
                str(state.get("status", "-")),
            )

    def _graph_width(self, widget_id: str, fallback: int = 38) -> int:
        try:
            width = self.query_one(widget_id, Static).size.width
        except Exception:
            return fallback
        return max(16, min(90, width - 4 if width > 6 else fallback))

    def _refresh_stats_panel(self) -> None:
        active = sum(1 for item in self.tasks.values() if item.get("status") == "running")
        done = sum(1 for item in self.tasks.values() if item.get("status") == "done")
        failed = sum(1 for item in self.tasks.values() if item.get("status") == "failed")

        percents: List[float] = []
        for item in self.tasks.values():
            total = int(item.get("total", 0))
            current = int(item.get("current", 0))
            if total > 0:
                percents.append(current / total)
        progress = sum(percents) / len(percents) if percents else 0.0

        self.progress_history.append(progress * 100)

        selected = self._selected_target()
        report = self.reports.get(selected) if selected else None
        if report is None and self.reports:
            report = next(reversed(self.reports.values()))

        total_subdomains = int(report.get("total_subdomains_found", 0)) if report else 0
        live_hosts = int(report.get("live_subdomains_count", 0)) if report else 0
        issues = len(report.get("summary", {}).get("security_issues", [])) if report else 0

        bar = gradient_bar(progress, width=34)
        stats_markup = (
            f"[bold #f8f8f2]Theme:[/] [#ffd866]{self.ui_theme}[/]   "
            f"[bold #f8f8f2]Intensity:[/] [#ffd866]{self.scan_intensity}[/]   "
            f"[bold #f8f8f2]Target:[/] [#66d9ef]{selected or '-'}[/]\n"
            f"[bold #f8f8f2]Active:[/] [#66d9ef]{active}[/]   "
            f"[bold #f8f8f2]Done:[/] [#a6e22e]{done}[/]   "
            f"[bold #f8f8f2]Failed:[/] [#ff6188]{failed}[/]"
        )
        self.query_one("#stats-body", Static).update(stats_markup)
        self.query_one("#finance-grid", Static).update(
            f"[#9ea6cc]Ending Cash Balance[/]      [#9ea6cc]Current Runway[/]\n"
            f"[bold #5fffb4]{total_subdomains:,} subdomains[/]          [bold #ff79c6]{live_hosts} live hosts[/]\n"
            f"[#9ea6cc]Net Burn[/]                 [#9ea6cc]Risk Flags[/]\n"
            f"[bold #5fffb4]{done - failed:+d} completed[/]              [bold #ffd866]{issues} findings[/]"
        )
        self.query_one("#company-form", Static).update(
            f"[#9ea6cc]Company Name[/]\\n[bold #d8dcff]{selected or 'Acme Inc'}[/]\\n\\n"
            f"[#9ea6cc]Legal Entity[/]\\n[bold #d8dcff]C Corp[/]\\n\\n"
            f"[#9ea6cc]Industry[/]\\n[bold #d8dcff]B2B / SaaS[/]\\n\\n"
            f"[#9ea6cc]Saved Targets[/] [bold #66d9ef]{len(self.targets)}[/]"
        )

        ports_graph = braille_sparkline(list(self.ports_history), width=self._graph_width("#ports-graph"))
        latency_graph = braille_sparkline(list(self.latency_history), width=self._graph_width("#latency-graph"))
        results_graph = braille_sparkline(list(self.progress_history), width=self._graph_width("#results-graph", 50))
        revenue_graph = block_sparkline(list(self.ports_history), width=self._graph_width("#revenue-graph", 20))

        self.query_one("#ports-graph", Static).update(
            f"[bold #72f1b8]Ports Found Over Time[/]\n{gradient_text(ports_graph, '#66d9ef', '#a6e22e')}"
        )
        self.query_one("#latency-graph", Static).update(
            f"[bold #ffb86c]Latency (ms) Over Time[/]\n{gradient_text(latency_graph, '#66d9ef', '#ff79c6')}"
        )
        self.query_one("#results-graph", Static).update(
            f"[bold #9ee8ff]Runway Burn Rate[/]\n{gradient_text(results_graph, '#f4d35e', '#5fffb4')}\n"
            f"[#9ea6cc]Pipeline:[/] {bar} [#f8f8f2]{int(progress * 100)}%[/]"
        )
        self.query_one("#revenue-graph", Static).update(
            f"[bold #8fe7ff]{revenue_graph}[/]\n[#9ea6cc]Real-time key metrics[/]"
        )
        self.query_one("#instant-body", Static).update(
            f"[#8fe7ff]◉[/] [bold #f8f8f2]{(live_hosts * 7) or 0}%[/] of dollar volume\\n"
            f"[#b987ff]◉[/] [bold #f8f8f2]{(100 - min(99, issues * 9)) if live_hosts else 0}%[/] finalized"
        )
        self.query_one("#compare-graph", Static).update(
            f"[bold #72f1b8]{block_sparkline(list(self.ports_history), width=26)}[/]"
        )

    def _update_history_from_report(self, report: Dict[str, Any]) -> None:
        live = report.get("live_subdomains", [])
        ports_found = sum(len(item.get("open_ports", [])) for item in live if isinstance(item, dict))

        response_times = []
        for item in live:
            if not isinstance(item, dict):
                continue
            value = item.get("response_time")
            if isinstance(value, (int, float)):
                response_times.append(float(value) * 1000.0)

        avg_latency = (sum(response_times) / len(response_times)) if response_times else 0.0

        self.ports_history.append(float(ports_found))
        self.latency_history.append(avg_latency)

    def _apply_theme(self, theme: str) -> None:
        if theme not in {"monokai", "dracula"}:
            return
        self.ui_theme = theme
        self.remove_class("theme-monokai")
        self.remove_class("theme-dracula")
        self.add_class(f"theme-{theme}")
        self._render_titles()
        self._render_hotkeys()

    def _apply_intensity(self, intensity: str) -> None:
        if intensity not in self.INTENSITY_PRESETS:
            return
        self.scan_intensity = intensity
        preset = self.INTENSITY_PRESETS[intensity]
        self.scan_config.max_concurrency = preset["max_concurrency"]
        self.scan_config.timeout = preset["timeout"]

    def _start_scan(self, target: str) -> None:
        if target in self.tasks and self.tasks[target].get("status") == "running":
            self._set_status(f"Scan already running for {target}")
            return

        self.tasks[target] = {
            "phase": "queued",
            "current": 0,
            "total": 0,
            "status": "running",
            "text": "Queued",
        }
        self._refresh_tasks_table()
        self._set_status(f"Starting scan for {target}")
        self._run_scan_worker(target)

    @work(group="recon", exclusive=False)
    async def _run_scan_worker(self, target: str) -> None:
        self.post_message(ScanLog(target, "[yellow]scan queued[/]"))

        async def log_callback(text: str) -> None:
            self.post_message(ScanLog(target, text))

        async def progress_callback(phase: str, current: int, total: int, text: str) -> None:
            self.post_message(ScanProgress(target, phase, current, total, text))

        config_snapshot = ScanConfig(**self.scan_config.to_dict())

        try:
            report = await run_enhanced_recon_async(
                domain=target,
                config=config_snapshot,
                log_callback=log_callback,
                progress_callback=progress_callback,
            )
            self.post_message(ScanFinished(target, report, None))
        except Exception as exc:
            self.post_message(ScanFinished(target, None, str(exc)))

    def _render_completion_summary(self, target: str, report: Dict[str, Any]) -> None:
        summary = Table(title=f"Summary: {target}", box=box.SIMPLE_HEAVY)
        summary.add_column("Metric", style="#66d9ef")
        summary.add_column("Value", style="#ffd866")
        summary.add_row("Subdomains", str(report.get("total_subdomains_found", 0)))
        summary.add_row("Live Hosts", str(report.get("live_subdomains_count", 0)))
        summary.add_row("Duration", f"{report.get('duration_seconds', 0)}s")
        self.query_one("#log-view", RichLog).write(summary)
        self._log_json(target, report.get("summary", {}))

    def _find_panel_id(self, widget: Optional[Widget]) -> Optional[str]:
        panel_ids = {
            "brand-card",
            "actions-card",
            "targets-panel",
            "stats-panel",
            "tasks-panel",
            "results-panel",
            "compare-card",
            "instant-card",
            "logs-panel",
            "export-card",
            "revenue-card",
        }
        cursor = widget
        while cursor is not None:
            if cursor.id in panel_ids:
                return cursor.id
            cursor = cursor.parent
        return None

    def _focus_panel(self, panel_id: str) -> None:
        if panel_id == "targets-panel":
            self.query_one("#target-list", ListView).focus()
            self._set_status("Targets panel focused")
        elif panel_id == "tasks-panel":
            self.query_one("#task-view", DataTable).focus()
            self._set_status("Tasks panel focused")
        elif panel_id == "results-panel":
            self.query_one("#results-view", DataTable).focus()
            self._set_status("Results panel focused")
        elif panel_id == "logs-panel":
            self.query_one("#log-view", RichLog).focus()
            self._set_status("Log panel focused")
        elif panel_id == "stats-panel":
            self._set_status("Metrics panel selected")
        elif panel_id in {"brand-card", "actions-card", "compare-card", "instant-card", "export-card", "revenue-card"}:
            self._set_status(f"{panel_id.replace('-', ' ').title()} selected")

    def _update_size_warning(self, width: int, height: int) -> None:
        too_small = width < self.MIN_WIDTH or height < self.MIN_HEIGHT
        self.query_one("#too-small-overlay", Container).display = too_small

    def _apply_layout_profile(self, width: int, height: int) -> None:
        if width >= 170 and height >= 48:
            profile = "ultra"
        elif width < 145 or height < 42:
            profile = "compact"
        else:
            profile = "wide"

        if profile == self.layout_profile:
            return

        self.layout_profile = profile
        self.remove_class("layout-compact")
        self.remove_class("layout-wide")
        self.remove_class("layout-ultra")
        self.add_class(f"layout-{profile}")

        if profile == "compact":
            self.query_one("#quote-blurb", Static).display = False
        else:
            self.query_one("#quote-blurb", Static).display = True

    def action_add_target(self) -> None:
        self.push_screen(AddTargetModal(), self._on_target_modal_result)

    def action_run_selected_scan(self) -> None:
        target = self._selected_target()
        if not target:
            self._set_status("No target selected")
            return
        self._start_scan(target)

    def action_open_settings(self) -> None:
        self.push_screen(SettingsOverlay(self.ui_theme, self.scan_intensity), self._on_settings_result)

    def action_clear_logs(self) -> None:
        self.query_one("#log-view", RichLog).clear()
        self._set_status("Log pane cleared")

    def action_export_selected(self) -> None:
        target = self._selected_target()
        if not target:
            self._set_status("No target selected")
            return

        report = self.reports.get(target)
        if not report:
            self._set_status(f"No scan report for {target}")
            return

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("*", "wildcard").replace("/", "_")
        output_path = Path("results") / f"{safe_target}_{stamp}.json"
        path = export_report(report, output_path)
        self._set_status(f"Exported report to {path}")
        self._log("system", f"[bold #a6e22e]exported[/] {path}")

    def action_focus_command(self) -> None:
        self.query_one("#command-input", Input).focus()

    def _on_target_modal_result(self, value: Optional[str]) -> None:
        if value is None:
            self._set_status("Add target canceled")
            return
        if self._add_target(value):
            self._log("system", f"target added: [bold #a6e22e]{value}[/]")

    def _on_settings_result(self, result: Optional[Dict[str, str]]) -> None:
        if result is None:
            self._set_status("Settings unchanged")
            return

        theme = result.get("theme", self.ui_theme)
        intensity = result.get("intensity", self.scan_intensity)

        self._apply_theme(theme)
        self._apply_intensity(intensity)

        self._set_status(f"Settings applied: theme={theme}, intensity={intensity}")
        self._log("system", f"theme set to [bold]{theme}[/], intensity [bold]{intensity}[/]")

    def _handle_command(self, command: str) -> None:
        if not command:
            return
        if command.startswith(":") or command.startswith("/"):
            command = command[1:]

        parts = command.split()
        action = parts[0].lower()
        args = parts[1:]

        if action in {"help", "?"}:
            self._log(
                "system",
                "commands: add <domain>, scan [domain], theme <monokai|dracula>, "
                "intensity <low|medium|high>, threads <n>, timeout <n>, nmap <on|off>, "
                "clear, export [domain]",
            )
            return

        if action == "add" and args:
            if self._add_target(args[0]):
                self._log("system", f"target added via command: [bold #a6e22e]{args[0]}[/]")
            return

        if action == "scan":
            target = normalize_domain(args[0]) if args else self._selected_target()
            if not target:
                self._set_status("No target selected")
                return
            if target not in self.targets:
                self._set_status(f"Unknown target: {target}")
                return
            self._start_scan(target)
            return

        if action == "theme" and args:
            self._apply_theme(args[0].lower())
            self._set_status(f"Theme set to {self.ui_theme}")
            return

        if action == "intensity" and args:
            self._apply_intensity(args[0].lower())
            self._set_status(f"Intensity set to {self.scan_intensity}")
            return

        if action == "threads" and args:
            try:
                self.scan_config.max_concurrency = max(1, min(200, int(args[0])))
                self._set_status(f"Concurrency set to {self.scan_config.max_concurrency}")
            except ValueError:
                self._set_status("Invalid thread count")
            return

        if action == "timeout" and args:
            try:
                self.scan_config.timeout = max(1, min(60, int(args[0])))
                self._set_status(f"Timeout set to {self.scan_config.timeout}s")
            except ValueError:
                self._set_status("Invalid timeout")
            return

        if action == "nmap" and args:
            flag = args[0].lower()
            if flag in {"on", "off"}:
                self.scan_config.enable_nmap = flag == "on"
                self._set_status(f"nmap set to {flag}")
            else:
                self._set_status("nmap must be on|off")
            return

        if action == "export":
            if args:
                target = normalize_domain(args[0])
                if target in self.targets:
                    self.query_one("#target-list", ListView).index = self.targets.index(target)
            self.action_export_selected()
            return

        if action == "clear":
            self.action_clear_logs()
            return

        self._set_status(f"Unknown command: {action}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn-add":
            self.action_add_target()
        elif button_id == "btn-scan":
            self.action_run_selected_scan()
        elif button_id == "btn-settings":
            self.action_open_settings()
        elif button_id == "btn-clear-logs":
            self.action_clear_logs()
        elif button_id == "btn-export":
            self.action_export_selected()
        elif button_id == "btn-assign":
            self._set_status("Automatic assignment pipeline armed")
        elif button_id == "btn-categorize":
            self._set_status("Categorization assistant ready")
        elif button_id == "btn-ai":
            self._set_status("AI categorizer primed")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id != "target-list":
            return
        target = self._selected_target()
        if target:
            self._set_status(f"Selected target: {target}")

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        if event.data_table.id != "results-view":
            return
        if event.column_key is None:
            return
        self.sort_column = str(event.column_key)
        self.sort_reverse = not self.sort_reverse
        self._refresh_results_table()
        direction = "desc" if self.sort_reverse else "asc"
        self._set_status(f"Sorted results by {self.sort_column} ({direction})")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "command-input":
            return
        command = event.value.strip()
        event.input.value = ""
        self._handle_command(command)

    def on_click(self, event: events.Click) -> None:
        panel_id = self._find_panel_id(event.widget)
        if panel_id:
            self._focus_panel(panel_id)

    def on_resize(self, event: events.Resize) -> None:
        self._apply_layout_profile(event.size.width, event.size.height)
        self._update_size_warning(event.size.width, event.size.height)

    def on_scan_log(self, message: ScanLog) -> None:
        self._log(message.target, message.text)

    def on_scan_progress(self, message: ScanProgress) -> None:
        self.tasks[message.target] = {
            "phase": message.phase,
            "current": message.current,
            "total": message.total,
            "status": "running",
            "text": message.text,
        }
        if message.total > 0:
            self.progress_history.append((message.current / message.total) * 100)

        self._refresh_tasks_table()
        self._set_status(f"{message.target}: {message.text}")

    def on_scan_finished(self, message: ScanFinished) -> None:
        if message.error:
            self.tasks[message.target] = {
                "phase": "error",
                "current": 0,
                "total": 0,
                "status": "failed",
                "text": message.error,
            }
            self._refresh_tasks_table()
            self._set_status(f"Scan failed for {message.target}")
            self._log(message.target, f"[bold #ff6188]error:[/] {message.error}")
            return

        report = message.report or {}
        self.reports[message.target] = report
        self.tasks[message.target] = {
            "phase": "complete",
            "current": 1,
            "total": 1,
            "status": "done",
            "text": "Completed",
        }

        self._update_history_from_report(report)
        self._refresh_tasks_table()
        self._refresh_results_table()
        self._render_completion_summary(message.target, report)
        self._set_status(f"Scan complete for {message.target}")


def main() -> None:
    app = NeuroSploitTUI()
    app.run()


if __name__ == "__main__":
    main()
