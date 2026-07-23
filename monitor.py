#!/usr/bin/env python3
"""
monitor.py — Azure Security Center Alert Monitor
=================================================
Pulls Microsoft Defender for Cloud alerts, scores and triages them,
maps to MITRE ATT&CK, and exports JSON / HTML / CSV reports.

Usage:
  python monitor.py                          # Pull live alerts from Azure
  python monitor.py --demo                   # Run with mock data (no creds needed)
  python monitor.py --severity High          # Filter by severity
  python monitor.py --output reports/ --html # Save HTML + JSON reports
  python monitor.py --schedule 15            # Run every 15 minutes
  python monitor.py --demo --csv --output reports/
  python monitor.py --demo --json-only       # JSON to stdout
"""

import argparse
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from core.alert_processor import process_alerts, summarize
from core.reporter import (
    print_report, build_json_report, save_json,
    build_html_report, save_html, save_csv
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

RESET = "\033[0m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; GRAY = "\033[90m"; BOLD = "\033[1m"


def run_once(args: argparse.Namespace) -> dict:
    """Execute one monitoring pass. Returns the JSON report dict."""

    # ── 1. Get alerts ──────────────────────────────────────────
    if args.demo:
        if not args.json_only:
            print(f"\n  {YELLOW}[DEMO MODE]{RESET} Using mock alerts — no Azure credentials needed.\n")
        from core.azure_client import _make_mock_alerts
        raw_alerts = _make_mock_alerts()
        subscription_id = "demo-subscription-001"
    else:
        from core.azure_client import AzureSecurityClient
        client = AzureSecurityClient()
        if not client.connect():
            print("\n  Authentication failed. Run with --demo to use mock data.\n")
            sys.exit(1)

        severity_filter = args.severity.split(",") if args.severity else None
        raw_alerts      = client.get_alerts(severity_filter=severity_filter)
        subscription_id = client.subscription_id

    # ── 2. Filter by severity if requested ────────────────────
    if args.severity and not args.demo:
        allowed = [s.strip() for s in args.severity.split(",")]
        raw_alerts = [a for a in raw_alerts if a.get("severity", "") in allowed]
    elif args.severity and args.demo:
        allowed    = [s.strip() for s in args.severity.split(",")]
        raw_alerts = [a for a in raw_alerts if a.get("severity", "") in allowed]

    # ── 3. Process ─────────────────────────────────────────────
    processed = process_alerts(raw_alerts)
    summary   = summarize(processed)

    # ── 4. Output ──────────────────────────────────────────────
    report = build_json_report(processed, summary, subscription_id)

    if args.json_only:
        print(json.dumps(report, indent=2, default=str))
        return report

    # CLI report
    print_report(processed, summary)

    # Save files
    if args.output:
        json_path = save_json(report, args.output)
        print(f"  {GREEN}JSON saved:{RESET} {json_path}")

        if args.html or args.html_only:
            html      = build_html_report(processed, summary, subscription_id)
            html_path = save_html(html, args.output)
            print(f"  {GREEN}HTML saved:{RESET} {html_path}")

        if args.csv:
            csv_path = save_csv(processed, args.output)
            print(f"  {GREEN}CSV saved: {RESET} {csv_path}")

        print()

    return report


def run_scheduled(args: argparse.Namespace) -> None:
    """Run monitor on a repeating schedule."""
    interval_sec = args.schedule * 60
    print(f"\n  {BOLD}Scheduled mode:{RESET} running every {args.schedule} minutes.")
    print(f"  Press Ctrl+C to stop.\n")

    run_count = 0
    while True:
        run_count += 1
        print(f"\n  {GRAY}─── Run #{run_count} — {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ───{RESET}")
        try:
            run_once(args)
        except KeyboardInterrupt:
            print("\n  Monitor stopped.")
            sys.exit(0)
        except Exception as e:
            log.error(f"Run #{run_count} failed: {e}")

        print(f"  {GRAY}Next run in {args.schedule} minutes...{RESET}")
        try:
            time.sleep(interval_sec)
        except KeyboardInterrupt:
            print("\n  Monitor stopped.")
            sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="Azure Security Center Alert Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python monitor.py --demo
  python monitor.py --demo --output reports/ --html
  python monitor.py --demo --severity High --csv --output reports/
  python monitor.py --demo --json-only
  python monitor.py --demo --schedule 15
  python monitor.py   (requires .env with Azure credentials)
        """
    )

    parser.add_argument("--demo",       action="store_true", help="Use mock alerts — no Azure credentials needed")
    parser.add_argument("--severity",   default="", metavar="LEVEL", help="Filter: High,Medium,Low (comma-separated)")
    parser.add_argument("--output","-o",metavar="DIR",                help="Save reports to this directory")
    parser.add_argument("--html",       action="store_true",          help="Generate HTML dashboard report")
    parser.add_argument("--html-only",  action="store_true",          help="HTML only, skip CLI output")
    parser.add_argument("--json-only",  action="store_true",          help="JSON to stdout only")
    parser.add_argument("--csv",        action="store_true",          help="Export CSV for Excel")
    parser.add_argument("--schedule",   type=int, metavar="MINUTES",  help="Run every N minutes")
    parser.add_argument("--verbose","-v",action="store_true",         help="Verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.schedule:
        run_scheduled(args)
    else:
        run_once(args)


if __name__ == "__main__":
    main()
