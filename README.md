# VTScanX

**Advanced VirusTotal Threat Intelligence Toolkit**

VTScanX is a modular Python CLI tool for automating threat intelligence lookups and malware analysis using the [VirusTotal API v3](https://developers.virustotal.com/reference/overview). Scan files, URLs, IP addresses, domains, and hashes — individually, in bulk, or interactively.

```
  Verdict : MALICIOUS
  Engines : 42/72 flagged as malicious
  Full report → output/scan_file_20240801_143022.json
```

---

## Features

- **File scanning** — upload and analyze binaries, scripts, documents
- **URL analysis** — check links for phishing and malware
- **IP reputation** — look up threat history for any IP address
- **Domain intelligence** — passive DNS, malware history, reputation
- **Hash lookup** — query existing VT reports by SHA256/MD5/SHA1
- **Batch scanning** — process a list of files, URLs, IPs, or domains in one shot
- **Directory scanning** — recursively scan entire folders concurrently
- **Interactive shell** — persistent `vtscanx>` prompt for rapid analysis
- **Structured JSON output** — timestamped reports saved automatically
- **Verdict scoring** — CLEAN / SUSPICIOUS / MEDIUM RISK / MALICIOUS
- **Rate-limit aware** — respects VT public API limits automatically
- **Persistent logging** — full logs saved to `logs/vtscanx.log`

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/VTScanX.git
cd VTScanX
pip install -r requirements.txt
```

**Configure your API key:**

```bash
cp config.ini.example config.ini
```

Edit `config.ini`:

```ini
[virustotal]
API_KEY = YOUR_VIRUSTOTAL_API_KEY_HERE

[settings]
OUTPUT_DIR = output
LOG_DIR = logs
```

Get a free API key at [virustotal.com](https://www.virustotal.com/gui/join-us).

---

## Usage

```bash
python main.py [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-f <path>` | Scan a single file |
| `-d <dir>` | Scan all files in a directory |
| `-u <url>` | Scan a URL |
| `-i <ip>` | Look up an IP address |
| `-do <domain>` | Look up a domain |
| `-H <hash>` | Look up a file hash (SHA256/MD5/SHA1) |
| `-b <file>` | Batch scan from a list file |
| `-o <dir>` | Override output directory |
| `-I` | Start interactive shell |
| `-q` | Suppress banner |

### Examples

```bash
# Scan a suspicious file
python main.py -f malware_sample.exe

# Scan a URL
python main.py -u https://suspicious-site.com

# Look up an IP
python main.py -i 185.220.101.45

# Look up a domain
python main.py -do malware-c2.xyz

# Look up a known hash
python main.py -H 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Batch scan (files, URLs, IPs, domains — mixed)
python main.py -b examples/batch.txt

# Scan all files in a directory
python main.py -d ./samples/

# Interactive mode
python main.py -I
```

### Batch File Format

```
# One item per line. Supports files, URLs, IPs, domains, hashes.
https://phishing-example.com
8.8.8.8
suspicious-domain.ru
/path/to/suspicious.dll
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

---

## Project Structure

```
VTScanX/
├── vtscanx/
│   ├── __init__.py       # Package metadata
│   ├── cli.py            # Argument parsing & interactive shell
│   ├── scanner.py        # VirusTotal API v3 client
│   ├── utils.py          # Hashing, logging, output helpers
│   └── config.py         # Config loader & validation
│
├── tests/
│   └── test_scanner.py   # Unit tests
│
├── examples/
│   └── batch.txt         # Example batch file
│
├── assets/
│   └── banner.txt        # ASCII banner
│
├── output/               # Scan results (auto-created, gitignored)
├── logs/                 # Log files (auto-created, gitignored)
│
├── main.py               # Entry point
├── setup.py
├── requirements.txt
├── config.ini.example    # Safe config template
├── .gitignore
├── LICENSE
└── README.md
```

---

## Output

Every scan creates a timestamped JSON file in `output/`:

```json
[
    {
        "file": "malware_sample.exe",
        "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "cached": false,
        "summary": {
            "verdict": "MALICIOUS",
            "malicious": 42,
            "suspicious": 3,
            "harmless": 0,
            "undetected": 27,
            "total_engines": 72,
            "scan_date": 1722520800,
            "reputation": -75
        },
        "report": { ... }
    }
]
```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

---

## API Version

VTScanX uses the **VirusTotal API v3** (`https://www.virustotal.com/api/v3/`), the current and actively supported version.

---

## Legal Disclaimer

> This tool is intended for **educational and authorized security research purposes only**.  
> Only scan files, URLs, and systems you own or have explicit permission to test.  
> The author is not responsible for misuse or illegal activity.

---

## License

MIT — see [LICENSE](LICENSE)

---

## Author

**Amine Bououd** — Cybersecurity  
Built on top of [Samurai v1.9](https://github.com/YOUR_USERNAME/VTScanX), refactored and upgraded to VTScanX v2.0.
