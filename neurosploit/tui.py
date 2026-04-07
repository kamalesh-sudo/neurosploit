from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich import box
from rich.syntax import Syntax
from rich.table import Table
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    ProgressBar,
    RichLog,
    Static,
)

from .core import ScanConfig, export_report, run_enhanced_recon_async

DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


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
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

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
            value = self.query_one("#target-input", Input).value.strip().lower()
            self.dismiss(value if value else None)
            return
        self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip().lower()
        self.dismiss(value if value else None)


class ConfigModal(ModalScreen[Optional[ScanConfig]]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, config: ScanConfig) -> None:
        super().__init__()
        self.current = config

    def compose(self) -> ComposeResult:
        with Container(classes="config-modal"):
            yield Static("Scan Configuration", classes="modal-title")
            yield Label("Mode (`full` or `mock`)")
            yield Input(value=self.current.mode, id="cfg-mode")
            yield Label("Max concurrency")
            yield Input(value=str(self.current.max_concurrency), id="cfg-concurrency")
            yield Label("Timeout (seconds)")
            yield Input(value=str(self.current.timeout), id="cfg-timeout")
            yield Checkbox("Certificate transparency lookup", value=self.current.enable_ct_logs, id="cfg-ct")
            yield Checkbox("DNS bruteforce", value=self.current.enable_dns_bruteforce, id="cfg-dns")
            yield Checkbox("HTTP probing", value=self.current.enable_http_probe, id="cfg-http")
            yield Checkbox("Deep analysis (ports and SSL)", value=self.current.enable_deep_analysis, id="cfg-deep")
            yield Checkbox("Nmap enrichment", value=self.current.enable_nmap, id="cfg-nmap")
            with Horizontal(classes="modal-actions"):
                yield Button("Save", variant="success", id="cfg-save")
                yield Button("Cancel", id="cfg-cancel")

    def on_mount(self) -> None:
        self.query_one("#cfg-mode", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cfg-save":
            self.dismiss(self._build_config())
            return
        self.dismiss(None)

    def _build_config(self) -> Optional[ScanConfig]:
        mode = self.query_one("#cfg-mode", Input).value.strip().lower() or "full"
        if mode not in {"full", "mock"}:
            return None

        try:
            concurrency = int(self.query_one("#cfg-concurrency", Input).value.strip() or "40")
            timeout = int(self.query_one("#cfg-timeout", Input).value.strip() or "5")
        except ValueError:
            return None

        return ScanConfig(
            mode=mode,
            max_concurrency=max(1, min(200, concurrency)),
            timeout=max(1, min(60, timeout)),
            enable_ct_logs=self.query_one("#cfg-ct", Checkbox).value,
            enable_dns_bruteforce=self.query_one("#cfg-dns", Checkbox).value,
            enable_http_probe=self.query_one("#cfg-http", Checkbox).value,
            enable_deep_analysis=self.query_one("#cfg-deep", Checkbox).value,
            enable_nmap=self.query_one("#cfg-nmap", Checkbox).value,
            nmap_top_ports=self.current.nmap_top_ports,
        )


class NeuroSploitTUI(App[None]):
    CSS_PATH = "tui.tcss"
    TITLE = "NeuroSploit"
    SUB_TITLE = "Interactive Recon Console"

    BINDINGS = [
        Binding("a", "add_target", "Add Target"),
        Binding("r", "run_selected_scan", "Scan"),
        Binding("c", "configure_scan", "Config"),
        Binding("v", "toggle_view", "Switch View"),
        Binding("l", "clear_logs", "Clear Logs"),
        Binding("e", "export_selected", "Export"),
        Binding("s", "sort_results", "Sort"),
        Binding("slash", "focus_command", "Command"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.targets: List[str] = self._load_targets_from_file()
        self.scan_config = ScanConfig()
        self.reports: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.result_rows: List[Dict[str, Any]] = []
        self.current_view = "logs"
        self.sort_column = "status_code"
        self.sort_reverse = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield Static("Targets", classes="panel-title")
                yield ListView(
                    *[ListItem(Label(target)) for target in self.targets],
                    id="target-list",
                )
                yield Static("Tools", classes="panel-title")
                yield Static(id="tool-box")
                with Horizontal(id="sidebar-controls"):
                    yield Button("Add", id="btn-add", variant="primary")
                    yield Button("Scan", id="btn-scan", variant="success")
                    yield Button("Config", id="btn-config")
            with Vertical(id="main"):
                yield Static("LOG VIEW", id="view-label")
                with Container(id="view-stack"):
                    yield RichLog(id="log-view", highlight=True, markup=True, wrap=True)
                    yield DataTable(id="results-view", zebra_stripes=True)
                yield DataTable(id="task-view", zebra_stripes=True)
                yield ProgressBar(total=None, show_eta=False, id="scan-progress")
                yield Input(placeholder=":help for commands", id="command-input")
                yield Static("Ready", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        self._init_tables()
        self._render_tool_box()
        self._set_status("Ready. Press 'a' to add target and 'r' to run scan.")
        self._log("system", "[bold #63e6be]NeuroSploit TUI initialized[/]")

    def _init_tables(self) -> None:
        results = self.query_one("#results-view", DataTable)
        results.add_columns(
            ("Target", "target"),
            ("Subdomain", "subdomain"),
            ("IP", "ip"),
            ("Status", "status_code"),
            ("Protocol", "protocol"),
            ("Server", "server"),
            ("Technology", "technology"),
            ("Ports", "ports"),
        )
        results.cursor_type = "row"

        tasks = self.query_one("#task-view", DataTable)
        tasks.add_columns(
            ("Target", "target"),
            ("Phase", "phase"),
            ("Progress", "progress"),
            ("Status", "status"),
        )

        self.query_one("#results-view", DataTable).display = False

    def _selected_target(self) -> Optional[str]:
        target_list = self.query_one("#target-list", ListView)
        if target_list.index is None:
            return None
        if target_list.index < 0 or target_list.index >= len(self.targets):
            return None
        return self.targets[target_list.index]

    def _load_targets_from_file(self) -> List[str]:
        data_file = Path(__file__).resolve().parent / "data" / "urls.txt"
        if not data_file.exists():
            return []
        targets = [line.strip().lower() for line in data_file.read_text().splitlines() if line.strip()]
        return list(dict.fromkeys(targets))

    def _add_target(self, target: str) -> bool:
        target = target.strip().lower()
        if not target or not DOMAIN_PATTERN.match(target):
            self._set_status(f"Invalid target: {target}")
            return False
        if target in self.targets:
            self._set_status(f"Target already present: {target}")
            return False

        self.targets.append(target)
        self.query_one("#target-list", ListView).append(ListItem(Label(target)))
        if len(self.targets) == 1:
            self.query_one("#target-list", ListView).index = 0
        self._set_status(f"Added target: {target}")
        return True

    def _render_tool_box(self) -> None:
        config_table = Table(box=box.SIMPLE_HEAVY)
        config_table.add_column("Setting", style="#a5d8ff")
        config_table.add_column("Value", style="#ffd43b")
        config_table.add_row("Mode", self.scan_config.mode)
        config_table.add_row("Concurrency", str(self.scan_config.max_concurrency))
        config_table.add_row("Timeout", f"{self.scan_config.timeout}s")
        config_table.add_row("CT Logs", "On" if self.scan_config.enable_ct_logs else "Off")
        config_table.add_row("DNS", "On" if self.scan_config.enable_dns_bruteforce else "Off")
        config_table.add_row("HTTP Probe", "On" if self.scan_config.enable_http_probe else "Off")
        config_table.add_row("Deep", "On" if self.scan_config.enable_deep_analysis else "Off")
        config_table.add_row("Nmap", "On" if self.scan_config.enable_nmap else "Off")

        self.query_one("#tool-box", Static).update(config_table)

    def _set_status(self, text: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.query_one("#status-bar", Static).update(f"[{timestamp}] {text}")

    def _log(self, target: str, text: str) -> None:
        self.query_one("#log-view", RichLog).write(f"[#4dabf7]{target}[/] {text}")

    def _refresh_tasks_table(self) -> None:
        tasks_table = self.query_one("#task-view", DataTable)
        tasks_table.clear(columns=False)
        for target, state in sorted(self.tasks.items()):
            total = state.get("total", 0)
            current = state.get("current", 0)
            if total:
                pct = f"{int((current / total) * 100):>3}% ({current}/{total})"
            else:
                pct = state.get("text", "-")
            tasks_table.add_row(
                target,
                state.get("phase", "-"),
                pct,
                state.get("status", "-"),
            )

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

    def _render_completion_summary(self, target: str, report: Dict[str, Any]) -> None:
        summary = Table(title=f"Recon Summary: {target}", box=box.SIMPLE)
        summary.add_column("Metric", style="#8ce99a")
        summary.add_column("Value", style="#ffd43b")
        summary.add_row("Subdomains", str(report.get("total_subdomains_found", 0)))
        summary.add_row("Live Hosts", str(report.get("live_subdomains_count", 0)))
        summary.add_row("Duration", f"{report.get('duration_seconds', 0)}s")
        self.query_one("#log-view", RichLog).write(summary)

        summary_json = json.dumps(report.get("summary", {}), indent=2)
        self.query_one("#log-view", RichLog).write(Syntax(summary_json, "json", word_wrap=True))

    async def _scan_target_worker(self, target: str) -> None:
        self.post_message(ScanLog(target, "[yellow]scan queued[/]"))

        async def log_callback(text: str) -> None:
            self.post_message(ScanLog(target, text))

        async def progress_callback(phase: str, current: int, total: int, text: str) -> None:
            self.post_message(ScanProgress(target, phase, current, total, text))

        try:
            report = await run_enhanced_recon_async(
                domain=target,
                config=self.scan_config,
                log_callback=log_callback,
                progress_callback=progress_callback,
            )
            self.post_message(ScanFinished(target, report, None))
        except Exception as exc:
            self.post_message(ScanFinished(target, None, str(exc)))

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
        self.run_worker(
            self._scan_target_worker(target),
            name=f"scan:{target}",
            group="scans",
            description=f"Recon scan for {target}",
            exit_on_error=False,
        )

    def action_add_target(self) -> None:
        self.push_screen(AddTargetModal(), self._on_target_modal_result)

    def _on_target_modal_result(self, value: Optional[str]) -> None:
        if value is None:
            self._set_status("Add target canceled")
            return
        if self._add_target(value):
            self._log("system", f"Added target [bold]{value}[/]")

    def action_configure_scan(self) -> None:
        self.push_screen(ConfigModal(self.scan_config), self._on_config_modal_result)

    def _on_config_modal_result(self, config: Optional[ScanConfig]) -> None:
        if config is None:
            self._set_status("Configuration canceled or invalid")
            return
        self.scan_config = config
        self._render_tool_box()
        self._set_status("Configuration updated")
        self._log("system", "Scan configuration updated")

    def action_run_selected_scan(self) -> None:
        target = self._selected_target()
        if not target:
            self._set_status("No target selected")
            return
        self._start_scan(target)

    def action_toggle_view(self) -> None:
        log_view = self.query_one("#log-view", RichLog)
        results_view = self.query_one("#results-view", DataTable)
        label = self.query_one("#view-label", Static)

        if self.current_view == "logs":
            self.current_view = "results"
            log_view.display = False
            results_view.display = True
            label.update("RESULTS VIEW")
        else:
            self.current_view = "logs"
            log_view.display = True
            results_view.display = False
            label.update("LOG VIEW")

    def action_clear_logs(self) -> None:
        self.query_one("#log-view", RichLog).clear()
        self._set_status("Logs cleared")

    def action_focus_command(self) -> None:
        self.query_one("#command-input", Input).focus()

    def action_export_selected(self) -> None:
        target = self._selected_target()
        if not target:
            self._set_status("No target selected")
            return

        report = self.reports.get(target)
        if not report:
            self._set_status(f"No results available for {target}")
            return

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("*", "wildcard").replace("/", "_")
        output_path = Path("results") / f"{safe_target}_{stamp}.json"
        path = export_report(report, output_path)
        self._set_status(f"Exported {target} to {path}")
        self._log("system", f"Exported report: [bold]{path}[/]")

    def action_sort_results(self) -> None:
        columns = ["target", "subdomain", "status_code", "server"]
        try:
            next_index = (columns.index(self.sort_column) + 1) % len(columns)
        except ValueError:
            next_index = 0
        self.sort_column = columns[next_index]
        self.sort_reverse = not self.sort_reverse
        self._refresh_results_table()
        direction = "desc" if self.sort_reverse else "asc"
        self._set_status(f"Sorted results by {self.sort_column} ({direction})")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn-add":
            self.action_add_target()
        elif button_id == "btn-scan":
            self.action_run_selected_scan()
        elif button_id == "btn-config":
            self.action_configure_scan()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id != "target-list":
            return
        selected = self._selected_target()
        if selected:
            self._set_status(f"Selected target: {selected}")

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        if event.data_table.id != "results-view":
            return
        self.sort_column = str(event.column_key)
        self.sort_reverse = not self.sort_reverse
        self._refresh_results_table()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "command-input":
            return
        command = event.value.strip()
        event.input.value = ""
        self._handle_command(command)

    def _handle_command(self, command: str) -> None:
        if not command:
            return
        if command.startswith(":") or command.startswith("/"):
            command = command[1:]

        parts = command.split()
        action = parts[0].lower()
        args = parts[1:]

        if action == "help":
            self._log(
                "system",
                "Commands: add <domain>, scan [domain], mode <full|mock>, threads <n>, timeout <n>, nmap <on|off>, view <logs|results>, clear, export [domain]",
            )
            return

        if action == "add" and args:
            value = args[0].strip().lower()
            if self._add_target(value):
                self._log("system", f"Target added via command: [bold]{value}[/]")
            return

        if action == "scan":
            target = args[0].lower() if args else self._selected_target()
            if not target:
                self._set_status("No target selected")
                return
            if target not in self.targets:
                self._set_status(f"Unknown target: {target}")
                return
            self._start_scan(target)
            return

        if action == "mode" and args:
            mode = args[0].lower()
            if mode in {"full", "mock"}:
                self.scan_config.mode = mode
                self._render_tool_box()
                self._set_status(f"Mode set to {mode}")
            else:
                self._set_status("Mode must be full or mock")
            return

        if action == "threads" and args:
            try:
                self.scan_config.max_concurrency = max(1, min(200, int(args[0])))
                self._render_tool_box()
                self._set_status(f"Concurrency set to {self.scan_config.max_concurrency}")
            except ValueError:
                self._set_status("Invalid concurrency value")
            return

        if action == "timeout" and args:
            try:
                self.scan_config.timeout = max(1, min(60, int(args[0])))
                self._render_tool_box()
                self._set_status(f"Timeout set to {self.scan_config.timeout}s")
            except ValueError:
                self._set_status("Invalid timeout value")
            return

        if action == "nmap" and args:
            flag = args[0].lower()
            if flag in {"on", "off"}:
                self.scan_config.enable_nmap = flag == "on"
                self._render_tool_box()
                self._set_status(f"Nmap set to {flag}")
            else:
                self._set_status("Nmap must be on or off")
            return

        if action == "view" and args:
            desired = args[0].lower()
            if desired in {"logs", "results"} and desired != self.current_view:
                self.action_toggle_view()
            return

        if action == "clear":
            self.action_clear_logs()
            return

        if action == "export":
            if args:
                target = args[0].lower()
                if target in self.targets:
                    target_list = self.query_one("#target-list", ListView)
                    target_list.index = self.targets.index(target)
            self.action_export_selected()
            return

        self._set_status(f"Unknown command: {action}")

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
        self._refresh_tasks_table()

        progress_bar = self.query_one("#scan-progress", ProgressBar)
        if message.total > 0:
            progress_bar.update(total=message.total, progress=message.current)
        else:
            progress_bar.update(total=None)

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
            self._log(message.target, f"[bold red]error:[/] {message.error}")
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
        self._refresh_tasks_table()
        self._refresh_results_table()
        self._render_completion_summary(message.target, report)

        self.query_one("#scan-progress", ProgressBar).update(total=1, progress=1)
        self._set_status(f"Scan complete for {message.target}")


def main() -> None:
    app = NeuroSploitTUI()
    app.run()


if __name__ == "__main__":
    main()
