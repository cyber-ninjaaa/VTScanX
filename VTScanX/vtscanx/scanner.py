import base64
import logging
import os
import time
import concurrent.futures

import requests

from .config import VT_API_BASE, REQUEST_LIMIT, TIME_FRAME
from .utils import get_file_hash, rate_sleep, summarize_report

logger = logging.getLogger('vtscanx')


class VirusTotalScanner:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {'x-apikey': api_key}

    # ------------------------------------------------------------------
    # Core request helper
    # ------------------------------------------------------------------

    def _get(self, endpoint: str, params: dict = None) -> dict | None:
        url = f"{VT_API_BASE}/{endpoint}"
        try:
            resp = requests.get(url, headers=self.headers, params=params, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as e:
            logger.error(f"HTTP error [{resp.status_code}] on GET {endpoint}: {e}")
        except requests.RequestException as e:
            logger.error(f"Request failed on GET {endpoint}: {e}")
        return None

    def _post(self, endpoint: str, data: dict = None, files: dict = None) -> dict | None:
        url = f"{VT_API_BASE}/{endpoint}"
        try:
            resp = requests.post(url, headers=self.headers, data=data, files=files, timeout=60)
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as e:
            logger.error(f"HTTP error [{resp.status_code}] on POST {endpoint}: {e}")
        except requests.RequestException as e:
            logger.error(f"Request failed on POST {endpoint}: {e}")
        return None

    # ------------------------------------------------------------------
    # File scanning
    # ------------------------------------------------------------------

    def scan_file(self, file_path: str) -> dict:
        """Upload and scan a file, then return its full report."""
        file_hash = get_file_hash(file_path)
        if not file_hash:
            return {'file': file_path, 'error': 'Could not hash file'}

        # Check cache first
        cached = self._get(f"files/{file_hash}")
        if cached and cached.get('data'):
            logger.info(f"Cache hit for {file_path} ({file_hash[:12]}…)")
            return {
                'file': file_path,
                'hash': file_hash,
                'cached': True,
                'report': cached,
                'summary': summarize_report(cached),
            }

        # Upload
        logger.info(f"Uploading {file_path}…")
        with open(file_path, 'rb') as f:
            upload_resp = self._post("files", files={'file': (os.path.basename(file_path), f)})

        if not upload_resp:
            return {'file': file_path, 'error': 'Upload failed'}

        analysis_id = upload_resp.get('data', {}).get('id')
        rate_sleep(REQUEST_LIMIT, TIME_FRAME)

        report = self._poll_analysis(analysis_id)
        return {
            'file': file_path,
            'hash': file_hash,
            'cached': False,
            'report': report,
            'summary': summarize_report(report),
        }

    def _poll_analysis(self, analysis_id: str, max_wait: int = 120) -> dict | None:
        """Poll an analysis ID until it completes."""
        if not analysis_id:
            return None
        waited = 0
        while waited < max_wait:
            result = self._get(f"analyses/{analysis_id}")
            status = result.get('data', {}).get('attributes', {}).get('status') if result else None
            if status == 'completed':
                return result
            logger.info(f"Analysis pending… waiting 15s (waited {waited}s)")
            time.sleep(15)
            waited += 15
        logger.warning("Analysis timed out.")
        return None

    # ------------------------------------------------------------------
    # URL scanning
    # ------------------------------------------------------------------

    def scan_url(self, url_to_scan: str) -> dict:
        url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip('=')

        # Check existing report
        cached = self._get(f"urls/{url_id}")
        if cached and cached.get('data'):
            return {
                'url': url_to_scan,
                'cached': True,
                'report': cached,
                'summary': summarize_report(cached, 'url'),
            }

        upload = self._post("urls", data={'url': url_to_scan})
        if not upload:
            return {'url': url_to_scan, 'error': 'Scan submission failed'}

        analysis_id = upload.get('data', {}).get('id')
        rate_sleep(REQUEST_LIMIT, TIME_FRAME)
        report = self._poll_analysis(analysis_id)
        return {
            'url': url_to_scan,
            'cached': False,
            'report': report,
            'summary': summarize_report(report, 'url'),
        }

    # ------------------------------------------------------------------
    # IP & Domain
    # ------------------------------------------------------------------

    def scan_ip(self, ip: str) -> dict:
        report = self._get(f"ip_addresses/{ip}")
        return {
            'ip': ip,
            'report': report,
            'summary': summarize_report(report, 'ip'),
        }

    def scan_domain(self, domain: str) -> dict:
        report = self._get(f"domains/{domain}")
        return {
            'domain': domain,
            'report': report,
            'summary': summarize_report(report, 'domain'),
        }

    # ------------------------------------------------------------------
    # Hash lookup
    # ------------------------------------------------------------------

    def get_file_report(self, file_hash: str) -> dict:
        report = self._get(f"files/{file_hash}")
        return {
            'hash': file_hash,
            'report': report,
            'summary': summarize_report(report),
        }

    # ------------------------------------------------------------------
    # Directory scan (concurrent)
    # ------------------------------------------------------------------

    def scan_directory(self, directory: str) -> list:
        all_files = [
            os.path.join(root, f)
            for root, _, files in os.walk(directory)
            for f in files
        ]
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = {executor.submit(self.scan_file, fp): fp for fp in all_files}
            for future in concurrent.futures.as_completed(futures):
                fp = futures[future]
                try:
                    results.append(future.result())
                except Exception as e:
                    logger.error(f"Error scanning {fp}: {e}")
                    results.append({'file': fp, 'error': str(e)})
        return results

    # ------------------------------------------------------------------
    # Batch scan
    # ------------------------------------------------------------------

    def scan_batch(self, batch_file: str) -> list:
        results = []
        with open(batch_file, 'r') as f:
            items = [line.strip() for line in f if line.strip()]

        for item in items:
            if os.path.isfile(item):
                results.append(self.scan_file(item))
            elif item.startswith(('http://', 'https://')):
                results.append(self.scan_url(item))
            elif self._looks_like_ip(item):
                results.append(self.scan_ip(item))
            elif len(item) in (32, 40, 64):
                results.append(self.get_file_report(item))
            else:
                results.append(self.scan_domain(item))
            rate_sleep(REQUEST_LIMIT, TIME_FRAME)

        return results

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        parts = value.split('.')
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
