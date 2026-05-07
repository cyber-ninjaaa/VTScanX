import argparse
import json
import os
import sys

from .config import load_config
from .scanner import VirusTotalScanner
from .utils import display_banner, save_results, setup_logging, timestamp


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='vtscanx',
        description='VTScanX — VirusTotal Threat Intelligence Toolkit',
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument('-f', '--file',      help='Scan a single file')
    parser.add_argument('-d', '--directory', help='Scan all files in a directory')
    parser.add_argument('-u', '--url',       help='Scan a URL')
    parser.add_argument('-i', '--ip',        help='Look up an IP address')
    parser.add_argument('-do', '--domain',   help='Look up a domain')
    parser.add_argument('-H', '--hash',      help='Look up a file by SHA256/MD5/SHA1 hash')
    parser.add_argument('-b', '--batch',     help='Batch scan from a file (one item per line)')
    parser.add_argument('-o', '--output',    help='Override output directory')
    parser.add_argument('-q', '--quiet',     action='store_true', help='Suppress banner')
    parser.add_argument('-I', '--interactive', action='store_true', help='Start interactive shell')
    return parser


def process_args(args, scanner: VirusTotalScanner, output_dir: str):
    ts = timestamp()
    result = None

    if args.file:
        result = scanner.scan_file(args.file)
        _print_and_save([result], os.path.join(output_dir, f'scan_file_{ts}.json'))

    elif args.directory:
        results = scanner.scan_directory(args.directory)
        _print_and_save(results, os.path.join(output_dir, f'scan_dir_{ts}.json'))
        return

    elif args.url:
        result = scanner.scan_url(args.url)
        _print_and_save([result], os.path.join(output_dir, f'scan_url_{ts}.json'))

    elif args.ip:
        result = scanner.scan_ip(args.ip)
        _print_and_save([result], os.path.join(output_dir, f'scan_ip_{ts}.json'))

    elif args.domain:
        result = scanner.scan_domain(args.domain)
        _print_and_save([result], os.path.join(output_dir, f'scan_domain_{ts}.json'))

    elif args.hash:
        result = scanner.get_file_report(args.hash)
        _print_and_save([result], os.path.join(output_dir, f'scan_hash_{ts}.json'))

    elif args.batch:
        results = scanner.scan_batch(args.batch)
        _print_and_save(results, os.path.join(output_dir, f'scan_batch_{ts}.json'))
        return

    else:
        print('[!] No target specified. Use -h for help.')


def _print_and_save(results, output_file: str):
    # Print summary to terminal
    for r in results:
        summary = r.get('summary', {})
        if summary:
            target = r.get('file') or r.get('url') or r.get('ip') or r.get('domain') or r.get('hash', '')
            verdict = summary.get('verdict', 'N/A')
            mal = summary.get('malicious', 0)
            total = summary.get('total_engines', 0)
            print(f"\n  Target  : {target}")
            print(f"  Verdict : {verdict}")
            print(f"  Engines : {mal}/{total} flagged as malicious")
        elif r.get('error'):
            print(f"\n  [ERROR] {r.get('error')}")

    # Full JSON output
    save_results(results, output_file)
    print(f"\n  Full report → {output_file}\n")


def interactive_mode(scanner: VirusTotalScanner, output_dir: str, parser: argparse.ArgumentParser):
    print("  Interactive mode. Type 'exit' or 'quit' to leave.\n")
    while True:
        try:
            line = input("vtscanx> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Goodbye.")
            break

        if line.lower() in ('exit', 'quit', 'q'):
            print("  Goodbye.")
            break
        if not line:
            continue

        try:
            parsed = parser.parse_args(line.split())
            process_args(parsed, scanner, output_dir)
        except SystemExit:
            pass


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.quiet:
        display_banner('assets/banner.txt')

    cfg = load_config()
    setup_logging(cfg['log_dir'])
    output_dir = args.output or cfg['output_dir']
    scanner = VirusTotalScanner(cfg['api_key'])

    if args.interactive:
        interactive_mode(scanner, output_dir, parser)
    else:
        process_args(args, scanner, output_dir)
