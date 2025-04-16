"""
Core scanner implementation for CacheXSSDetector.
Coordinates the scanning process and integrates various detection modules.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import json
import asyncio
from pathlib import Path

from ..utils.logger import get_logger
from ..request.http_client import HTTPClient
from .url_manipulator import URLManipulator
from .cache_analyzer import CacheAnalyzer
from .xss_payload import PayloadGenerator
from .response_analyzer import ResponseAnalyzer

logger = get_logger(__name__)

@dataclass
class Vulnerability:
    """Data class for storing vulnerability information."""
    type: str
    url: str
    description: str
    severity: str
    payload: Optional[str] = None
    evidence: Optional[str] = None
    timestamp: str = datetime.now().isoformat()

@dataclass
class ScanResult:
    """Data class for storing scan results."""
    target_url: str
    vulnerabilities: List[Vulnerability]
    scan_time: float
    total_requests: int
    start_time: str
    end_time: str
    scanner_version: str = "0.1.0"

class Scanner:
    """
    Main scanner class that coordinates the scanning process.
    """
    
    def __init__(
        self,
        url: str,
        config: Optional[Dict[str, Any]] = None,
        proxy: Optional[str] = None,
        verbose: bool = False
    ):
        """
        Initialize scanner with target URL and configuration.
        
        Args:
            url (str): Target URL to scan
            config (Optional[Dict[str, Any]]): Scanner configuration
            proxy (Optional[str]): Proxy URL
            verbose (bool): Enable verbose output
        """
        self.url = url
        self.config = config or {}
        self.proxy = proxy
        self.verbose = verbose
        
        # Initialize components
        self.http_client = HTTPClient(
            proxy=proxy,
            verify_ssl=self.config.get('proxy', {}).get('verify_ssl', True),
            timeout=self.config.get('scanner', {}).get('timeout', 30)
        )
        
        self.url_manipulator = URLManipulator()
        self.cache_analyzer = CacheAnalyzer()
        self.payload_generator = PayloadGenerator()
        self.response_analyzer = ResponseAnalyzer()
        
        self.vulnerabilities: List[Vulnerability] = []
        self.total_requests = 0
        
        logger.info(f"Scanner initialized for target: {url}")

    async def scan_url(self, url: str) -> List[Vulnerability]:
        """
        Scan a single URL for cache-based XSS vulnerabilities.
        
        Args:
            url (str): URL to scan
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Generate URL variations
            url_variations = self.url_manipulator.generate_variations(url)
            
            # Test each URL variation
            for variant_url in url_variations:
                # Analyze cache behavior
                cache_info = await self.cache_analyzer.analyze(
                    self.http_client,
                    variant_url
                )
                
                if cache_info.is_cached:
                    # Generate payloads based on cache behavior
                    payloads = self.payload_generator.generate(
                        cache_info=cache_info,
                        max_length=self.config.get('payloads', {}).get('max_length', 1000)
                    )
                    
                    # Test each payload
                    for payload in payloads:
                        response = await self.http_client.get(
                            variant_url,
                            headers={'X-Cache-Test': payload}
                        )
                        self.total_requests += 1
                        
                        # Analyze response for vulnerabilities
                        if self.response_analyzer.is_vulnerable(response, payload):
                            vuln = Vulnerability(
                                type="Cache-Based XSS",
                                url=variant_url,
                                description="Cache-based XSS vulnerability detected",
                                severity="High",
                                payload=payload,
                                evidence=self.response_analyzer.get_evidence(response)
                            )
                            vulnerabilities.append(vuln)
                            logger.warning(f"Vulnerability found in {variant_url}")
                            
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {str(e)}")
            
        return vulnerabilities

    async def run_async(self) -> ScanResult:
        """
        Run the scanner asynchronously.
        
        Returns:
            ScanResult: Results of the scan
        """
        start_time = datetime.now()
        start_time_str = start_time.isoformat()
        
        try:
            # Get base URL variations
            urls_to_scan = self.url_manipulator.generate_variations(self.url)
            
            # Scan all URLs concurrently
            tasks = [self.scan_url(url) for url in urls_to_scan]
            results = await asyncio.gather(*tasks)
            
            # Combine results
            for vulns in results:
                self.vulnerabilities.extend(vulns)
                
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            raise
            
        end_time = datetime.now()
        scan_time = (end_time - start_time).total_seconds()
        
        return ScanResult(
            target_url=self.url,
            vulnerabilities=self.vulnerabilities,
            scan_time=scan_time,
            total_requests=self.total_requests,
            start_time=start_time_str,
            end_time=end_time.isoformat()
        )

    def run(self) -> ScanResult:
        """
        Run the scanner synchronously.
        
        Returns:
            ScanResult: Results of the scan
        """
        return asyncio.run(self.run_async())

    def save_report(self, output_path: str) -> None:
        """
        Save scan results to a file.
        
        Args:
            output_path (str): Path to save the report
        """
        try:
            report_file = Path(output_path)
            report_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert vulnerabilities to dictionary format
            report_data = {
                "target_url": self.url,
                "scan_time": datetime.now().isoformat(),
                "total_requests": self.total_requests,
                "vulnerabilities": [
                    {
                        "type": v.type,
                        "url": v.url,
                        "description": v.description,
                        "severity": v.severity,
                        "payload": v.payload,
                        "evidence": v.evidence,
                        "timestamp": v.timestamp
                    }
                    for v in self.vulnerabilities
                ]
            }
            
            # Save report as JSON
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=4)
                
            logger.info(f"Report saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to save report: {str(e)}")
            raise

if __name__ == "__main__":
    # Test scanner functionality
    async def test_scanner():
        scanner = Scanner("http://example.com")
        results = await scanner.run_async()
        print(f"Found {len(results.vulnerabilities)} vulnerabilities")
        
    asyncio.run(test_scanner())
