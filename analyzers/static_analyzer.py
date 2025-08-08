# analyzers/static_analyzer.py
import hashlib
import os
import re
import math
import requests
from collections import Counter
from typing import Dict, Any, Optional, Tuple, List

# Import the new config utility
from utils.config import get_config_value

# Use try-except blocks for optional dependencies
try:
    import pefile
except ImportError:
    pefile = None
try:
    import yara
except ImportError:
    yara = None
try:
    import magic
except ImportError:
    magic = None

class StaticAnalyzer:
    """
    Performs comprehensive static analysis on a file.
    """
    def __init__(self, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found at: {file_path}")
        self.file_path = file_path
        self.yara_rules = self._compile_yara_rules()

    def _compile_yara_rules(self) -> Optional[yara.Rules]:
        # This function remains unchanged
        if not yara:
            print("[!] yara-python is not installed. Skipping YARA analysis.")
            return None
        try:
            rules_dir = os.path.join(os.path.dirname(__file__), '..', 'rules')
            if not os.path.isdir(rules_dir):
                print(f"[!] Rules directory not found at: {rules_dir}")
                return None

            filepaths = {fn: os.path.join(rules_dir, fn) for fn in os.listdir(rules_dir) if fn.endswith((".yar", ".yara"))}
            if not filepaths:
                print("[!] No YARA rule files found in the rules directory.")
                return None

            print(f"[*] Compiling YARA rules from {len(filepaths)} file(s)...")
            return yara.compile(filepaths=filepaths)
        except yara.Error as e:
            print(f"[!] Error compiling YARA rules: {e}")
            return None

    def _enrich_ips(self, ips: list) -> list:
        """Enriches found IP addresses with Geo-IP data using the endpoint from .env."""
        enriched_data = []
        try:
            # Get the API endpoint from the .env file
            api_endpoint = get_config_value("IP_API_ENDPOINT")
        except ValueError as e:
            print(f"[!] Could not get IP API endpoint: {e}")
            return enriched_data

        for ip in set(ips):
            try:
                response = requests.get(f"{api_endpoint}{ip}", timeout=5)
                if response.status_code == 200 and response.json().get('status') == 'success':
                    data = response.json()
                    enriched_data.append({
                        'ip': ip, 
                        'country': data.get('country', 'N/A'), 
                        'city': data.get('city', 'N/A'), 
                        'isp': data.get('isp', 'N/A')
                    })
            except requests.RequestException:
                continue
        return enriched_data

    # All other analysis methods (_compute_hashes, _check_file_type, etc.)
    # and the main run_analysis method remain unchanged.
    def _compute_hashes(self) -> Dict[str, str]:
        """Computes MD5, SHA-1, and SHA-256 hashes for the file."""
        hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
        try:
            with open(self.file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    for algo in hashes.values():
                        algo.update(chunk)
            return {name: algo.hexdigest() for name, algo in hashes.items()}
        except IOError as e:
            print(f"[!] Error reading file for hashing: {e}")
            return {}

    def _check_file_type(self) -> Tuple[int, str, str]:
        """Checks for file type extension mismatches."""
        file_extension = os.path.splitext(self.file_path)[1].lower()
        if not magic:
            return 0, "python-magic not installed.", "Unknown"
        try:
            true_file_type = magic.from_file(self.file_path)
            is_executable = 'executable' in true_file_type.lower()
            if is_executable and file_extension not in ['.exe', '.dll', '.scr', '.com', '.elf', '']:
                finding = f"CRITICAL: File extension is '{file_extension}' but true type is an executable!"
                return 50, finding, true_file_type
            return 0, "", true_file_type
        except Exception as e:
            return 0, "", f"Could not determine file type: {e}"

    def _calculate_file_entropy(self) -> Tuple[int, str, float]:
        """Calculates file entropy to detect packing or encryption."""
        try:
            with open(self.file_path, 'rb') as f:
                byte_counts = Counter(f.read())
            file_size = sum(byte_counts.values())
            if file_size == 0:
                return 0, "", 0.0

            entropy = -sum((count / file_size) * math.log2(count / file_size) for count in byte_counts.values())

            if entropy > 7.5:
                finding = f"High overall file entropy ({entropy:.2f}), indicating potential packing or encryption."
                return 15, finding, entropy
            return 0, "", entropy
        except IOError:
            return 0, "", 0.0

    def _analyze_strings(self) -> Tuple[int, List[str], Dict]:
        """Extracts and analyzes strings for suspicious keywords, IPs, and URLs."""
        score, findings, results = 0, [], {'found_ips': [], 'found_urls': [], 'found_keywords': []}
        suspicious_keywords = [b'powershell', b'invoke-expression', b'downloadstring', b'/bin/bash', b'nc -e']

        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()

            results['found_ips'] = [ip.decode('ascii', 'ignore') for ip in re.findall(rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content)]
            if results['found_ips']:
                score += len(results['found_ips'])
                findings.append(f"Found {len(results['found_ips'])} IP address(es).")

            results['found_urls'] = [url.decode('ascii', 'ignore') for url in re.findall(rb'https?://[^\s"\'<>]+', content)]
            if results['found_urls']:
                score += len(results['found_urls']) * 2
                findings.append(f"Found {len(results['found_urls'])} URL(s).")

            for keyword in suspicious_keywords:
                if keyword in content:
                    results['found_keywords'].append(keyword.decode('ascii'))
            if results['found_keywords']:
                score += len(results['found_keywords']) * 3
                findings.append(f"Found suspicious keywords: {results['found_keywords']}.")

        except IOError:
            findings.append("Could not read file for string analysis.")

        return score, findings, results

    def _analyze_pe(self) -> Tuple[int, List[str], Dict]:
        """Analyzes PE file structure for anomalies."""
        if not pefile:
            return 0, [], {"error": "pefile not installed."}

        score, findings, pe_info = 0, [], {}
        try:
            pe = pefile.PE(self.file_path)
            if len(pe.sections) > 8:
                score += 10
                findings.append(f"High number of PE sections ({len(pe.sections)}), may indicate packing.")
            pe_info['sections_count'] = len(pe.sections)
            return score, findings, pe_info
        except pefile.PEFormatError:
            return 0, [], {"error": "Not a valid PE file."}
        except Exception as e:
            return 0, [], {"error": f"PE analysis failed: {e}"}

    def _analyze_yara(self) -> Tuple[int, List[str], Dict]:
        """Matches file against compiled YARA rules."""
        if not self.yara_rules:
            return 0, [], {'error': 'YARA not installed or rules not compiled.'}

        score, findings, results = 0, [], {}
        try:
            matches = self.yara_rules.match(self.file_path)
            matched_rules = [match.rule for match in matches]
            if matched_rules:
                score += len(matched_rules) * 20
                findings.append(f"YARA rule matches: {', '.join(matched_rules)}")
            results['matches'] = matched_rules
            return score, findings, results
        except yara.Error as e:
            return 0, [], {'error': str(e)}

    def run_analysis(self) -> Dict[str, Any]:
        """Executes all static analysis steps and returns a comprehensive report."""
        report = {'static_analysis_summary': []}
        score_breakdown = {}

        type_score, type_finding, true_type = self._check_file_type()
        entropy_score, entropy_finding, entropy_val = self._calculate_file_entropy()
        string_score, string_findings, string_results = self._analyze_strings()
        yara_score, yara_findings, yara_results = self._analyze_yara()
        pe_score, pe_findings, pe_results = self._analyze_pe()

        score_breakdown['File Type Mismatch'] = type_score
        score_breakdown['High Entropy'] = entropy_score
        score_breakdown['Suspicious Strings'] = string_score
        score_breakdown['YARA Matches'] = yara_score
        score_breakdown['PE Anomalies'] = pe_score
        if type_finding: report['static_analysis_summary'].append(type_finding)
        if entropy_finding: report['static_analysis_summary'].append(entropy_finding)
        report['static_analysis_summary'].extend(string_findings)
        report['static_analysis_summary'].extend(yara_findings)
        report['static_analysis_summary'].extend(pe_findings)

        report['score_breakdown'] = score_breakdown
        report['static_analysis_score'] = sum(score_breakdown.values())
        report['file_info'] = {
            'file_name': os.path.basename(self.file_path),
            'file_size_bytes': os.path.getsize(self.file_path),
            'file_extension': os.path.splitext(self.file_path)[1].lower(),
            'true_file_type': true_type,
            'entropy': entropy_val
        }
        report['hashes'] = self._compute_hashes()
        report['string_analysis'] = string_results
        report['yara_analysis'] = yara_results
        report['pe_analysis'] = pe_results

        if string_results.get('found_ips'):
            report['ip_enrichment'] = self._enrich_ips(string_results['found_ips'])

        if not report['static_analysis_summary']:
            report['static_analysis_summary'].append("No suspicious indicators found.")

        return report
