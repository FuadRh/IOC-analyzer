# analyzers/vt_analyzer.py
import requests
import time
from typing import Dict, Any, Optional

class VTAnalyzer:
    """
    Queries the VirusTotal API for file and URL enrichment.
    This class handles communication with VirusTotal to retrieve scan reports
    for file hashes and URLs, including handling API rate limits.
    """
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        """
        Initializes the VTAnalyzer with the API key.
        Args:
            api_key (str): Your VirusTotal API key.
        """
        self.api_key = api_key
        self.headers = {
            "x-apikey": self.api_key,
            "accept": "application/json"
        }

    def _handle_request(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """
        A helper method to send requests to the VirusTotal API and handle responses.
        Args:
            endpoint (str): The API endpoint to query (e.g., '/files/{hash}').
        Returns:
            Optional[Dict[str, Any]]: The JSON response from the API as a dictionary,
                                      or None if an error occurs.
        """
        try:
            response = requests.get(f"{self.BASE_URL}{endpoint}", headers=self.headers)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                print("[-] Indicator not found in VirusTotal database.")
                return {'error': 'Not Found'}
            elif response.status_code == 429:
                print("[!] Rate limit exceeded. Waiting for 60 seconds...")
                time.sleep(60)
                return self._handle_request(endpoint) # Retry the request
            elif response.status_code == 401:
                print("[!] Authentication error. Check your VirusTotal API key.")
                return {'error': 'Authentication Failed'}
            else:
                print(f"[!] An API error occurred: {response.status_code} - {response.text}")
                return {'error': f"API Error {response.status_code}"}
        except requests.exceptions.RequestException as e:
            print(f"[!] A network error occurred: {e}")
            return {'error': 'Network Error'}

    def query_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Queries VirusTotal for a report on a given file hash.
        Args:
            file_hash (str): The MD5, SHA-1, or SHA-256 hash of the file.
        Returns:
            Dict[str, Any]: A dictionary containing the summarized VT report.
        """
        print(f"[*] Querying VirusTotal for hash: {file_hash}")
        endpoint = f"/files/{file_hash}"
        response_data = self._handle_request(endpoint)

        if not response_data or 'error' in response_data:
            return {'virustotal_report': response_data or {'error': 'Failed to get report'}}

        # Simplify the massive VT report into key-value pairs
        attributes = response_data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        summary = {
            'detection_ratio': f"{stats.get('malicious', 0)} / {sum(stats.values())}",
            'scan_date': attributes.get('last_analysis_date'),
            'positives': stats.get('malicious', 0),
            'total_scans': sum(stats.values()),
            'scan_results': attributes.get('last_analysis_results', {}),
            'link': f"https://www.virustotal.com/gui/file/{file_hash}"
        }
        print("[+] VirusTotal report retrieved successfully.")
        return {'virustotal_report': summary}

    def query_url(self, url: str) -> Dict[str, Any]:
        """
        Queries VirusTotal for a report on a given URL.
        Note: The free API cannot search for URLs directly, it requires submitting
        them for analysis first and then retrieving the report. This function
        is a placeholder for that logic. For simplicity, we'll query by the URL's ID.
        Args:
            url (str): The URL to analyze.
        Returns:
            Dict[str, Any]: A dictionary containing the summarized VT report.
        """
        # VT API requires a URL ID, which is a base64 of the URL.
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        print(f"[*] Querying VirusTotal for URL: {url}")
        endpoint = f"/urls/{url_id}"
        response_data = self._handle_request(endpoint)

        if not response_data or 'error' in response_data:
            return {'virustotal_report': response_data or {'error': 'Failed to get report'}}

        attributes = response_data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        summary = {
            'detection_ratio': f"{stats.get('malicious', 0)} / {sum(stats.values())}",
            'scan_date': attributes.get('last_analysis_date'),
            'positives': stats.get('malicious', 0),
            'total_scans': sum(stats.values()),
            'scan_results': attributes.get('last_analysis_results', {}),
            'link': f"https://www.virustotal.com/gui/url/{url_id}"
        }
        print("[+] VirusTotal report retrieved successfully.")
        return {'virustotal_report': summary}
