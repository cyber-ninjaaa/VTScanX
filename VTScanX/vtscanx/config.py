import configparser
import os
import sys
from pathlib import Path

CONFIG_FILE = 'config.ini'
DEFAULT_OUTPUT_DIR = 'output'
DEFAULT_LOG_DIR = 'logs'
REQUEST_LIMIT = 4       # Requests per minute (public API)
TIME_FRAME = 60         # Seconds
VT_API_BASE = 'https://www.virustotal.com/api/v3'


def load_config():
    config = configparser.ConfigParser()

    if not os.path.exists(CONFIG_FILE):
        print(f"[!] Config file '{CONFIG_FILE}' not found.")
        print(f"    Copy 'config.ini.example' to 'config.ini' and add your API key.")
        sys.exit(1)

    config.read(CONFIG_FILE)

    if not config.has_option('virustotal', 'API_KEY') or not config['virustotal']['API_KEY']:
        print("[!] Missing or empty VirusTotal API key in config.ini.")
        sys.exit(1)

    api_key = config['virustotal']['API_KEY']
    output_dir = config.get('settings', 'OUTPUT_DIR', fallback=DEFAULT_OUTPUT_DIR)
    log_dir = config.get('settings', 'LOG_DIR', fallback=DEFAULT_LOG_DIR)

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    return {
        'api_key': api_key,
        'output_dir': output_dir,
        'log_dir': log_dir,
    }
