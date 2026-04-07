import argparse
import asyncio
import json
from pathlib import Path


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
    from .core import ScanConfig, export_report, run_enhanced_recon_async

    if not args.target:
        print("error: target domain is required in headless mode")
        return 2

    config = ScanConfig(
        mode=args.mode,
        max_concurrency=max(1, min(200, args.threads)),
        timeout=max(1, min(60, args.timeout)),
        enable_nmap=args.nmap,
    )

    report = asyncio.run(run_enhanced_recon_async(domain=args.target, config=config))

    if args.output:
        output_path = export_report(report, args.output)
        print(f"exported report to {output_path}")
    else:
        print(json.dumps(report, indent=2, default=str))

    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

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
