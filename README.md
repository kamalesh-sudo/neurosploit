# NeuroSploit

Interactive recon framework with an async Textual TUI.

## What Changed in v3

- Multi-pane TUI layout (sidebar, live logs, tasks, results table, status footer)
- Async recon engine using `asyncio`
- Background scan execution through Textual worker API (`run_worker`)
- Live progress bar and active-task table
- Rich-powered summary rendering and JSON syntax-highlighted logs
- Command bar + modal input for targets and scan config
- Keyboard-driven navigation and quick actions

## Installation

```bash
git clone https://github.com/iharishragav/neurosploit.git
cd neurosploit
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install .
```

## Run TUI

```bash
neurosploit
```

## Default Hotkeys

- `a` add target
- `r` run scan for selected target
- `c` open scan configuration modal
- `v` toggle logs/results view
- `s` sort results table
- `l` clear log pane
- `e` export selected target report
- `/` focus command bar
- `q` quit

## Command Bar

Use `:help` in the command bar for built-in commands.

Examples:

```text
:add example.com
:scan
:scan api.example.com
:mode mock
:threads 80
:timeout 8
:nmap on
:export example.com
```

## Headless Mode

```bash
neurosploit --headless example.com --threads 60 --timeout 7 --output results/example.json
```

Headless mode now validates and normalizes targets, so inputs like `https://example.com/path` are cleaned to `example.com`.

## Target List Hygiene

- `neurosploit/data/urls.txt` is treated as the default target list for TUI startup.
- Invalid or duplicate entries are automatically removed when the app loads.

## Notes

- `nmap` enrichment is optional and requires `nmap` installed on the host.
- Local LLM analysis hooks can still be built on top using `build_ai_prompt` in `neurosploit/core.py`.
