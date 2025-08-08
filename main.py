# main.py
import argparse
import os
from datetime import datetime
from typing import Dict

# Import our custom modules
from analyzers.static_analyzer import StaticAnalyzer
from analyzers.vt_analyzer import VTAnalyzer
from utils.config import get_config_value
from utils.exporter import export_all_formats 

# The print_pretty_report, analyze_file, and analyze_url functions remain unchanged.
def print_pretty_report(report: Dict, indicator: str):
    """Prints a formatted, human-readable summary of the analysis report to the console."""
    print("\n" + "="*25 + " ANALYSIS REPORT " + "="*25)
    print(f"Indicator:\t{indicator}")
    print(f"Report Time:\t{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-"*67)

    if 'file_info' in report:
        file_info = report['file_info']
        print("\n[+] FILE INFORMATION")
        print(f"  File Name:\t{file_info.get('file_name', 'N/A')}")
        print(f"  File Size:\t{file_info.get('file_size_bytes', 'N/A')} bytes")
        print(f"  Entropy:\t{file_info.get('entropy', 0.0):.4f}")
        hashes = report.get('hashes', {})
        print(f"  MD5:\t\t{hashes.get('md5', 'N/A')}")
        print(f"  SHA-1:\t{hashes.get('sha1', 'N/A')}")
        print(f"  SHA-256:\t{hashes.get('sha256', 'N/A')}")

    print("\n[+] STATIC ANALYSIS")
    static_score = report.get('static_analysis_score', 0)
    print(f"  Static Score:\t\t{static_score}")
    summary = report.get('static_analysis_summary', ["N/A"])
    print("  Static Findings:")
    for item in summary:
        print(f"    - {item}")

    yara_report = report.get('yara_analysis', {})
    if yara_report and 'error' not in yara_report:
        print("\n[+] YARA SCAN")
        matches = yara_report.get('matches', [])
        if matches:
            print(f"  Matches Found: {', '.join(matches)}")
        else:
            print("  No YARA rule matches found.")

    vt_report = report.get('virustotal_report', {})
    vt_positives = 0
    if vt_report and 'error' not in vt_report:
        vt_positives = vt_report.get('positives', 0)
        total = vt_report.get('total_scans', 0)
        print("\n[+] VIRUSTOTAL ENRICHMENT")
        print(f"  Detections:\t{vt_positives} / {total}")
        print(f"  VT Link:\t{vt_report.get('link', 'N/A')}")
    elif 'error' in vt_report:
        print("\n[+] VIRUSTOTAL ENRICHMENT")
        print(f"  Error:\tCould not retrieve report ({vt_report['error']})")

    threat_score = static_score + (vt_positives * 2)
    verdict = "CLEAN"
    if threat_score > 20:
        verdict = "MALICIOUS"
    elif threat_score > 5:
        verdict = "SUSPICIOUS"

    print("\n[+] FINAL VERDICT")
    print(f"  Overall Threat Score:\t{threat_score}")
    print(f"  Recommendation:\t{verdict}")
    print("\n" + "="*67)

def analyze_file(file_path: str, vt_analyzer: VTAnalyzer) -> Dict:
    """Orchestrates the full analysis workflow for a single file."""
    print(f"\n\n--- Analyzing {os.path.basename(file_path)} ---")
    static_analyzer = StaticAnalyzer(file_path)
    static_report = static_analyzer.run_analysis()

    file_hash = static_report.get('hashes', {}).get('sha256')
    if file_hash:
        vt_report = vt_analyzer.query_hash(file_hash)
        static_report.update(vt_report)
    else:
        static_report['virustotal_report'] = {'error': 'Could not compute hash for VT query.'}
    return static_report

def analyze_url(url: str, vt_analyzer: VTAnalyzer) -> Dict:
    """Orchestrates the analysis for a URL."""
    print(f"\n\n--- Analyzing {url} ---")
    vt_report = vt_analyzer.query_url(url)
    final_report = {'static_analysis_score': 0, 'static_analysis_summary': ['N/A for URLs']}
    final_report.update(vt_report)
    return final_report

def main():
    """Main function to parse arguments and drive the analysis."""
    parser = argparse.ArgumentParser(description="SOC Tier 1 Analysis Framework.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--files", nargs='+', help="One or more full paths to the files to analyze.")
    group.add_argument("--url", help="A single URL to analyze.")
    args = parser.parse_args()

    try:
        # Using the new config function to get the API key
        vt_api_key = get_config_value('VIRUSTOTAL_API_KEY')
        vt_analyzer = VTAnalyzer(api_key=vt_api_key)

        if args.files:
            for file_path in args.files:
                if not os.path.exists(file_path):
                    print(f"[ERROR] File not found: {file_path}. Skipping.")
                    continue
                report = analyze_file(file_path, vt_analyzer)
                print_pretty_report(report, os.path.basename(file_path))
                export_all_formats(report, os.path.basename(file_path))

        elif args.url:
            report = analyze_url(args.url, vt_analyzer)
            print_pretty_report(report, args.url)
            export_all_formats(report, args.url)

    except (FileNotFoundError, KeyError, ValueError) as e:
        print(f"[ERROR] A configuration error occurred: {e}")
    except Exception as e:
        print(f"[FATAL ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
