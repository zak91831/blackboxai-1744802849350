"""
False Positive Reducer for CacheXSSDetector.
Applies heuristics and thresholds to reduce false positives in vulnerability detection.
"""

from typing import List, Dict, Any
from ..core.scanner import Vulnerability
from ..utils.logger import get_logger

logger = get_logger(__name__)

class FalsePositiveReducer:
    """
    Reduces false positives by applying configurable heuristics and filters.
    """

    def __init__(self, confidence_threshold: float = 0.6, severity_levels: List[str] = None):
        """
        Initialize the reducer.
        
        Args:
            confidence_threshold (float): Minimum confidence to consider a vulnerability valid
            severity_levels (List[str]): List of severity levels to include (e.g., ['High', 'Critical'])
        """
        self.confidence_threshold = confidence_threshold
        self.severity_levels = severity_levels or ['High', 'Critical']

    def filter_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """
        Filter vulnerabilities to reduce false positives.
        
        Args:
            vulnerabilities (List[Vulnerability]): List of detected vulnerabilities
            
        Returns:
            List[Vulnerability]: Filtered list of vulnerabilities
        """
        filtered = []
        for vuln in vulnerabilities:
            try:
                # Check confidence attribute if present
                confidence = getattr(vuln, 'confidence', 1.0)
                severity = getattr(vuln, 'severity', 'Low')

                if confidence >= self.confidence_threshold and severity in self.severity_levels:
                    filtered.append(vuln)
                else:
                    logger.debug(f"Filtered out false positive: {vuln}")
            except Exception as e:
                logger.error(f"Error filtering vulnerability: {str(e)}")
        logger.info(f"Filtered vulnerabilities: {len(filtered)} out of {len(vulnerabilities)}")
        return filtered

if __name__ == "__main__":
    # Example usage
    from dataclasses import dataclass

    @dataclass
    class DummyVuln:
        type: str
        url: str
        description: str
        severity: str
        confidence: float

    vulns = [
        DummyVuln("XSS", "http://example.com", "Test vuln 1", "High", 0.9),
        DummyVuln("XSS", "http://example.com", "Test vuln 2", "Low", 0.7),
        DummyVuln("XSS", "http://example.com", "Test vuln 3", "Critical", 0.5),
        DummyVuln("XSS", "http://example.com", "Test vuln 4", "High", 0.4),
    ]

    reducer = FalsePositiveReducer(confidence_threshold=0.6, severity_levels=['High', 'Critical'])
    filtered = reducer.filter_vulnerabilities(vulns)
    print(f"Filtered vulnerabilities: {len(filtered)}")
    for v in filtered:
        print(v)
