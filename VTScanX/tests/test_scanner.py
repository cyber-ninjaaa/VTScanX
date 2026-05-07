import unittest
from unittest.mock import patch, MagicMock
from vtscanx.utils import get_file_hash, format_verdict, summarize_report
from vtscanx.scanner import VirusTotalScanner


class TestUtils(unittest.TestCase):

    def test_format_verdict_clean(self):
        self.assertEqual(format_verdict(0, 70), 'CLEAN')

    def test_format_verdict_malicious(self):
        self.assertEqual(format_verdict(40, 70), 'MALICIOUS')

    def test_format_verdict_suspicious(self):
        self.assertEqual(format_verdict(5, 70), 'SUSPICIOUS')

    def test_format_verdict_unknown(self):
        self.assertEqual(format_verdict(0, 0), 'UNKNOWN')

    def test_summarize_report_empty(self):
        self.assertEqual(summarize_report({}), {})

    def test_summarize_report(self):
        mock_report = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 10,
                        'suspicious': 2,
                        'harmless': 50,
                        'undetected': 10,
                    },
                    'reputation': -5,
                }
            }
        }
        summary = summarize_report(mock_report)
        self.assertEqual(summary['malicious'], 10)
        self.assertEqual(summary['total_engines'], 72)
        self.assertEqual(summary['verdict'], 'MEDIUM RISK')


class TestScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = VirusTotalScanner('fake_api_key')

    def test_looks_like_ip(self):
        self.assertTrue(VirusTotalScanner._looks_like_ip('8.8.8.8'))
        self.assertFalse(VirusTotalScanner._looks_like_ip('example.com'))
        self.assertFalse(VirusTotalScanner._looks_like_ip('999.0.0.1'))

    @patch('vtscanx.scanner.requests.get')
    def test_scan_ip(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {'data': {'attributes': {'last_analysis_stats': {
            'malicious': 0, 'suspicious': 0, 'harmless': 70, 'undetected': 0
        }}}}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = self.scanner.scan_ip('8.8.8.8')
        self.assertEqual(result['ip'], '8.8.8.8')
        self.assertIn('summary', result)


if __name__ == '__main__':
    unittest.main()
