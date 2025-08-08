# tests/test_vt_analyzer.py
import unittest
from unittest.mock import patch, Mock
import sys
import os

# Add the parent directory to the Python path to allow importing from 'analyzers'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzers.vt_analyzer import VTAnalyzer

class TestVTAnalyzer(unittest.TestCase):
    """
    Unit tests for the VTAnalyzer class.
    
    These tests use mocking to simulate API responses from VirusTotal,
    allowing us to test the class's logic without making real network requests.
    """

    def setUp(self):
        """
        Set up a new VTAnalyzer instance before each test.
        """
        self.api_key = "fake_api_key_for_testing"
        self.analyzer = VTAnalyzer(api_key=self.api_key)

    @patch('analyzers.vt_analyzer.requests.get')
    def test_query_hash_success(self, mock_get):
        """
        Test a successful hash query to VirusTotal.
        """
        # 1. Prepare the mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60},
                    "last_analysis_date": 1672531199,
                    "last_analysis_results": {"Kaspersky": {"category": "malicious"}}
                }
            }
        }
        mock_get.return_value = mock_response

        # 2. Call the function being tested
        test_hash = "some_sha256_hash"
        result = self.analyzer.query_hash(test_hash)

        # 3. Assert the results are what we expect
        report = result['virustotal_report']
        self.assertEqual(report['positives'], 5)
        self.assertEqual(report['total_scans'], 66) # 5 + 1 + 60
        self.assertEqual(report['detection_ratio'], "5 / 66")
        self.assertIn("Kaspersky", report['scan_results'])
        mock_get.assert_called_once_with(
            f"https://www.virustotal.com/api/v3/files/{test_hash}",
            headers=self.analyzer.headers
        )

    @patch('analyzers.vt_analyzer.requests.get')
    def test_query_url_success(self, mock_get):
        """
        Test a successful URL query to VirusTotal.
        """
        # 1. Prepare the mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 10, "suspicious": 0, "harmless": 80},
                    "last_analysis_date": 1672531200,
                    "last_analysis_results": {"Google Safebrowsing": {"category": "malicious"}}
                }
            }
        }
        mock_get.return_value = mock_response

        # 2. Call the function
        test_url = "http://example-malicious-site.com"
        result = self.analyzer.query_url(test_url)

        # 3. Assert the results
        report = result['virustotal_report']
        self.assertEqual(report['positives'], 10)
        self.assertEqual(report['total_scans'], 90)
        self.assertEqual(report['detection_ratio'], "10 / 90")
        self.assertIn("Google Safebrowsing", report['scan_results'])

    @patch('analyzers.vt_analyzer.requests.get')
    def test_query_not_found(self, mock_get):
        """
        Test the handling of a 404 Not Found error from the API.
        """
        # 1. Prepare the mock response for a 404 error
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        # 2. Call the function
        test_hash = "unknown_hash"
        result = self.analyzer.query_hash(test_hash)

        # 3. Assert the error is handled correctly
        self.assertEqual(result['virustotal_report']['error'], 'Not Found')

    @patch('analyzers.vt_analyzer.requests.get')
    def test_query_auth_error(self, mock_get):
        """
        Test the handling of a 401 Authentication Failed error.
        """
        # 1. Prepare the mock response for a 401 error
        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        # 2. Call the function
        test_hash = "any_hash"
        result = self.analyzer.query_hash(test_hash)

        # 3. Assert the error is handled correctly
        self.assertEqual(result['virustotal_report']['error'], 'Authentication Failed')

if __name__ == '__main__':
    unittest.main()
