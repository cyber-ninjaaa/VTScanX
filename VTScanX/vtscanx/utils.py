import hashlib
import logging
import json
import os
import time
from datetime import datetime
from pathlib import Path

logger = logging.getLogger('vtscanx')


def setup_logging(log_dir: str):
    log_file = os.path.join(log_dir, 'vtscanx.log')
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(),
        ]
    )


def get_file_hash(file_path: str) -> str | None:
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return None
    except PermissionError:
        logger.error(f"Permission denied: {file_path}")
        return None


def save_results(results, output_file: str):
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        logger.info(f"Results saved to {output_file}")
    except IOError as e:
        logger.error(f"Failed to save results: {e}")


def timestamp() -> str:
    return datetime.now().strftime('%Y%m%d_%H%M%S')


def rate_sleep(request_limit: int, time_frame: int):
    """Sleep to respect rate limit."""
    time.sleep(time_frame / request_limit)


def display_banner(banner_file: str = 'assets/banner.txt'):
    try:
        with open(banner_file, 'r') as f:
            print(f.read())
    except FileNotFoundError:
        print("VTScanX — VirusTotal Threat Intelligence Toolkit\n")


def format_verdict(positives: int, total: int) -> str:
    if total == 0:
        return "UNKNOWN"
    ratio = positives / total
    if ratio == 0:
        return "CLEAN"
    elif ratio < 0.1:
        return "SUSPICIOUS"
    elif ratio < 0.4:
        return "MEDIUM RISK"
    else:
        return "MALICIOUS"


def summarize_report(report: dict, resource_type: str = 'file') -> dict:
    """Extract key fields from a VT v3 report into a clean summary."""
    if not report:
        return {}

    attrs = report.get('data', {}).get('attributes', {})
    stats = attrs.get('last_analysis_stats', {})
    positives = stats.get('malicious', 0)
    total = sum(stats.values()) if stats else 0

    return {
        'verdict': format_verdict(positives, total),
        'malicious': positives,
        'suspicious': stats.get('suspicious', 0),
        'harmless': stats.get('harmless', 0),
        'undetected': stats.get('undetected', 0),
        'total_engines': total,
        'scan_date': attrs.get('last_analysis_date', 'N/A'),
        'reputation': attrs.get('reputation', 'N/A'),
    }
