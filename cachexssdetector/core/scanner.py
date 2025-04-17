"""
Optimized Core Scanner Implementation for CacheXSSDetector.
Implements parallel scanning with resource management and improved error handling.
"""

from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from datetime import datetime
import json
import asyncio
from pathlib import Path
import time
from concurrent.futures import ThreadPoolExecutor

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
    response_time: Optional[float] = None
    cache_info: Optional[Dict[str, Any]] = None

@dataclass
class ScanResult:
    """Enhanced data class for storing detailed scan results."""
    target_url: str
    vulnerabilities: List[Vulnerability]
    scan_time: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    start_time: str
    end_time: str
    scanner_version: str = "0.2.0"
    error_summary: Optional[Dict[str, int]] = None
    performance_metrics: Optional[Dict[str, Any]] = None

class Scanner:
    """
    Optimized scanner class with parallel processing and resource management.
    """
    
    def __init__(
        self,
        url: str,
        config: Optional[Dict[str, Any]] = None,
        proxy: Optional[str] = None,
        verbose: bool = False,
        max_concurrent_scans: int = 10,
        max_urls_per_scan: int = 100
    ):
        """
        Initialize scanner with enhanced configuration.
        
        Args:
            url (str): Target URL to scan
            config (Optional[Dict[str, Any]]): Scanner configuration
            proxy (Optional[str]): Proxy URL
            verbose (bool): Enable verbose output
            max_concurrent_scans (int): Maximum number of concurrent URL scans
            max_urls_per_scan (int): Maximum number of URLs to scan
        """
        self.url = url
        self.config = config or {}
        self.proxy = proxy
        self.verbose = verbose
        self.max_concurrent_scans = max_concurrent_scans
        self.max_urls_per_scan = max_urls_per_scan
        
        # Initialize components with optimized settings
        self.http_client = HTTPClient(
            proxy=proxy,
            verify_ssl=self.config.get('proxy', {}).get('verify_ssl', True),
            timeout=self.config.get('scanner', {}).get('timeout', 30),
            max_connections=max_concurrent_scans * 2,
            max_connections_per_host=max_concurrent_scans
        )
        
        self.url_manipulator = URLManipulator(max_variations=max_urls_per_scan)
        self.cache_analyzer = CacheAnalyzer()
        self.payload_generator = PayloadGenerator()
        self.response_analyzer = ResponseAnalyzer()
        
        # Scan state tracking
        self.vulnerabilities: List[Vulnerability] = []
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.error_counts: Dict[str, int] = {}
        self.scan_semaphore = asyncio.Semaphore(max_concurrent_scans)
        self.scanned_urls: Set[str] = set()
        
        # Performance metrics
        self.response_times: List[float] = []
        
        logger.info(
            f"Scanner initialized for target: {url} "
            f"(max concurrent: {max_concurrent_scans}, "
            f"max URLs: {max_urls_per_scan})"
        )

    async def scan_url(self, url: str) -> List[Vulnerability]:
        """
        Scan a single URL for cache-based XSS vulnerabilities with improved error handling.
        
        Args:
            url (str): URL to scan
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities
        """
        vulnerabilities = []
        normalized_url = self.url_manipulator.normalize_url(url)
        
        if normalized_url in self.scanned_urls:
            logger.debug(f"Skipping already scanned URL: {url}")
            return vulnerabilities
            
        self.scanned_urls.add(normalized_url)
        
        try:
            async with self.scan_semaphore:
                # Analyze cache behavior first
                start_time = time.time()
                cache_info = await self.cache_analyzer.analyze(
                    self.http_client,
                    url
                )
                self.total_requests += 1
                self.successful_requests += 1
                response_time = time.time() - start_time
                self.response_times.append(response_time)
                
                if not cache_info.is_cached:
                    logger.debug(f"URL not cached, skipping: {url}")
                    return vulnerabilities
                
                # Generate and test payloads
                cache_info_dict = cache_info.to_dict() if cache_info else None
                payloads = self.payload_generator.generate(
                    cache_info=cache_info_dict,
                    max_length=self.config.get('payloads', {}).get('max_length', 1000)
                )
                
                for payload in payloads:
                    try:
                        start_time = time.time()
                        response = await self.http_client.get(
                            url,
                            headers={'X-Cache-Test': payload}
                        )
                        response_time = time.time() - start_time
                        self.response_times.append(response_time)
                        
                        self.total_requests += 1
                        self.successful_requests += 1
                        
                        if self.response_analyzer.is_vulnerable(response, payload):
                            vuln = Vulnerability(
                                type="Cache-Based XSS",
                                url=url,
                                description="Cache-based XSS vulnerability detected",
                                severity="High",
                                payload=payload,
                                evidence=self.response_analyzer.get_evidence(response),
                                response_time=response_time,
                                cache_info=cache_info.to_dict()
                            )
                            vulnerabilities.append(vuln)
                            logger.warning(f"Vulnerability found in {url}")
                            
                    except Exception as e:
                        self.failed_requests += 1
                        error_type = type(e).__name__
                        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
                        logger.error(f"Error testing payload on {url}: {str(e)}")
                        
        except Exception as e:
            self.failed_requests += 1
            error_type = type(e).__name__
            self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
            logger.error(f"Error scanning URL {url}: {str(e)}")
            
        return vulnerabilities

    async def run_async(self) -> ScanResult:
        """
        Run the scanner asynchronously with parallel processing.
        
        Returns:
            ScanResult: Detailed results of the scan
        """
        start_time = datetime.now()
        start_time_str = start_time.isoformat()
        
        try:
            # Generate URL variations efficiently
            urls_to_scan = self.url_manipulator.generate_variations(self.url)
            logger.info(f"Generated {len(urls_to_scan)} URLs to scan")
            
            # Create tasks for parallel scanning
            tasks = []
            for url in urls_to_scan[:self.max_urls_per_scan]:
                tasks.append(self.scan_url(url))
            
            # Run tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, list):
                    self.vulnerabilities.extend(result)
                else:
                    logger.error(f"Task failed: {str(result)}")
                    self.failed_requests += 1
                    error_type = type(result).__name__
                    self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
                
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            raise
        finally:
            # Close all client sessions
            await self.http_client.close_all_sessions()
            
        end_time = datetime.now()
        scan_time = (end_time - start_time).total_seconds()
        
        # Calculate performance metrics
        performance_metrics = {
            'avg_response_time': sum(self.response_times) / len(self.response_times) if self.response_times else 0,
            'min_response_time': min(self.response_times) if self.response_times else 0,
            'max_response_time': max(self.response_times) if self.response_times else 0,
            'total_urls': len(urls_to_scan),
            'scanned_urls': len(self.scanned_urls),
            'success_rate': (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0
        }
        
        return ScanResult(
            target_url=self.url,
            vulnerabilities=self.vulnerabilities,
            scan_time=scan_time,
            total_requests=self.total_requests,
            successful_requests=self.successful_requests,
            failed_requests=self.failed_requests,
            start_time=start_time_str,
            end_time=end_time.isoformat(),
            error_summary=self.error_counts,
            performance_metrics=performance_metrics
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
        Save detailed scan results to a file.
        
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
                "successful_requests": self.successful_requests,
                "failed_requests": self.failed_requests,
                "error_summary": self.error_counts,
                "performance_metrics": {
                    "avg_response_time": sum(self.response_times) / len(self.response_times) if self.response_times else 0,
                    "min_response_time": min(self.response_times) if self.response_times else 0,
                    "max_response_time": max(self.response_times) if self.response_times else 0,
                    "total_urls_scanned": len(self.scanned_urls)
                },
                "vulnerabilities": [
                    {
                        "type": v.type,
                        "url": v.url,
                        "description": v.description,
                        "severity": v.severity,
                        "payload": v.payload,
                        "evidence": v.evidence,
                        "timestamp": v.timestamp,
                        "response_time": v.response_time,
                        "cache_info": v.cache_info
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
        scanner = Scanner(
            "http://example.com",
            max_concurrent_scans=5,
            max_urls_per_scan=50
        )
        results = await scanner.run_async()
        print(f"Found {len(results.vulnerabilities)} vulnerabilities")
        print(f"Performance: {results.performance_metrics}")
        
    asyncio.run(test_scanner())
