# tests/test_static_analyzer.py
import unittest
import os
import sys
import hashlib # Import hashlib to calculate hashes within the test

# Add the parent directory to the Python path to allow importing from 'analyzers'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzers.static_analyzer import StaticAnalyzer

class TestStaticAnalyzer(unittest.TestCase):
    """
    Unit tests for the StaticAnalyzer class.
    
    These tests create temporary files to validate hashing and PE analysis logic.
    """

    def setUp(self):
        """
        Create a temporary dummy file before each test.
        """
        self.test_file_name = "test_file.tmp"
        # Write the file in binary mode to ensure consistency.
        with open(self.test_file_name, "wb") as f:
            f.write(b"This is a test file for the SOC framework.")

    def tearDown(self):
        """
        Clean up by removing the temporary file after each test.
        """
        if os.path.exists(self.test_file_name):
            os.remove(self.test_file_name)

    def test_file_not_found(self):
        """
        Test that the analyzer raises FileNotFoundError for a non-existent file.
        """
        with self.assertRaises(FileNotFoundError):
            StaticAnalyzer("non_existent_file.xyz")

    def test_compute_hashes(self):
        """
        Test that file hashes are computed correctly and consistently.
        """
        # First, calculate the ground truth hashes directly from the file we created.
        # This makes the test robust against any minor environmental differences.
        expected_hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        with open(self.test_file_name, 'rb') as f:
            content = f.read()
            for algo in expected_hashes.values():
                algo.update(content)

        expected_hashes = {name: algo.hexdigest() for name, algo in expected_hashes.items()}

        # Now, run the analyzer and check if it produces the same hashes.
        analyzer = StaticAnalyzer(self.test_file_name)
        analyzer_hashes = analyzer._compute_hashes()

        self.assertEqual(analyzer_hashes, expected_hashes)

    def test_run_analysis_non_pe_file(self):
        """
        Test the full analysis run on a non-PE file.
        """
        analyzer = StaticAnalyzer(self.test_file_name)
        report = analyzer.run_analysis()

        # Check that basic info and hashes are present
        self.assertIn('file_info', report)
        self.assertIn('hashes', report)
        self.assertEqual(report['file_info']['file_name'], self.test_file_name)

        # Check that PE analysis section indicates it's not a PE file
        self.assertIn('pe_analysis', report)
        self.assertIn("Not a PE file", report['pe_analysis'])

if __name__ == '__main__':
    unittest.main()
