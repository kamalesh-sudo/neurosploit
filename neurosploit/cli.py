import argparse
import asyncio
import json
from pathlib import Path

from .targets import is_valid_domain, normalize_domain


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NeuroSploit interactive recon framework")
    parser.add_argument(
        "target",
        nargs="?",
        help="Target domain for headless mode (example.com)",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run a single scan in CLI mode and print JSON output",
    )
    parser.add_argument(
        "--mode",
        choices=["full", "mock"],
        default="full",
        help="Scan mode for headless mode",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=40,
        help="Max concurrency for headless mode",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Timeout in seconds for network operations",
    )
    parser.add_argument(
        "--nmap",
        action="store_true",
        help="Enable nmap enrichment in headless mode",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional output path to export JSON report",
    )
    return parser


def _run_headless(args: argparse.Namespace) -> int:
    target = normalize_domain(args.target or "")
    if not target:
        print("error: target domain is required in headless mode")
        return 2
    if not is_valid_domain(target):
        print(f"error: invalid target domain: {args.target!r}")
        return 2

    try:
        from .core import ScanConfig, export_report, run_enhanced_recon_async
    except ModuleNotFoundError as exc:
        print(
            "error: missing runtime dependency for headless scan. "
            "Install requirements with: pip install -r requirements.txt\n"
            f"details: {exc}"
        )
        return 2

    config = ScanConfig(
        mode=args.mode,
        max_concurrency=max(1, min(200, args.threads)),
        timeout=max(1, min(60, args.timeout)),
        enable_nmap=args.nmap,
    )

    report = asyncio.run(run_enhanced_recon_async(domain=target, config=config))

    if args.output:
        output_path = export_report(report, args.output)
        print(f"exported report to {output_path}")
    else:
        print(json.dumps(report, indent=2, default=str))

    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.target and not args.headless:
        parser.error("target argument is only supported with --headless")
        return

    if args.headless:
        raise SystemExit(_run_headless(args))

    try:
        from .tui import main as run_tui
    except ImportError as exc:
        parser.error(
            "TUI dependencies are missing. Install with: pip install textual rich\n"
            f"Import error details: {exc}"
        )
        return

    run_tui()


if __name__ == "__main__":
    main()
