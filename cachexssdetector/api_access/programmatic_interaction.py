"""
Programmatic Interaction API for CacheXSSDetector.
Provides programmatic access to scanning and reporting features.
"""

from typing import Optional, Dict, Any
from ..core.scanner import Scanner, ScanResult
from ..utils.logger import get_logger

logger = get_logger(__name__)

class CacheXSSDetectorAPI:
    """
    API class to expose scanning and reporting functionalities.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def scan(self, url: str, proxy: Optional[str] = None, verbose: bool = False) -> ScanResult:
        """
        Perform a scan on the given URL.
        
        Args:
            url (str): Target URL
            proxy (Optional[str]): Proxy URL
            verbose (bool): Verbose output
            
        Returns:
            ScanResult: Scan results
        """
        try:
            scanner = Scanner(url, config=self.config, proxy=proxy, verbose=verbose)
            result = scanner.run()
            return result
        except Exception as e:
            logger.error(f"API scan failed: {str(e)}")
            raise

    def save_report(self, scan_result: ScanResult, output_path: str) -> bool:
        """
        Save scan results to a file.
        
        Args:
            scan_result (ScanResult): Scan results
            output_path (str): Path to save report
            
        Returns:
            bool: True if successful
        """
        try:
            scanner = Scanner(scan_result.target_url, config=self.config)
            scanner.vulnerabilities = scan_result.vulnerabilities
            scanner.total_requests = scan_result.total_requests
            scanner.save_report(output_path)
            return True
        except Exception as e:
            logger.error(f"API save report failed: {str(e)}")
            return False

if __name__ == "__main__":
    api = CacheXSSDetectorAPI()
    url = "http://example.com"
    print(f"Starting scan for {url}")
    result = api.scan(url)
    print(f"Scan completed. Found {len(result.vulnerabilities)} vulnerabilities.")
