"""
Cache Hit/Miss Detector for CacheXSSDetector.
Detects cache hits and misses by analyzing HTTP response headers and behavior.
"""

from typing import List, Dict, Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)

class CacheHitMissDetector:
    """
    Detects cache hits and misses during testing by analyzing response headers.
    """

    def __init__(self):
        self.cache_hit_indicators = [
            'X-Cache',
            'X-Cache-Hit',
            'CF-Cache-Status',
            'Age'
        ]

    def is_cache_hit(self, headers: Dict[str, str]) -> bool:
        """
        Determine if a response indicates a cache hit.
        
        Args:
            headers (Dict[str, str]): HTTP response headers
            
        Returns:
            bool: True if cache hit detected, False otherwise
        """
        try:
            for header in self.cache_hit_indicators:
                value = headers.get(header, '').lower()
                if value and ('hit' in value or value == '1'):
                    logger.debug(f"Cache hit detected via header {header}: {value}")
                    return True
            return False
        except Exception as e:
            logger.error(f"Error detecting cache hit: {str(e)}")
            return False

    def is_cache_miss(self, headers: Dict[str, str]) -> bool:
        """
        Determine if a response indicates a cache miss.
        
        Args:
            headers (Dict[str, str]): HTTP response headers
            
        Returns:
            bool: True if cache miss detected, False otherwise
        """
        try:
            for header in self.cache_hit_indicators:
                value = headers.get(header, '').lower()
                if value and ('miss' in value or value == '0'):
                    logger.debug(f"Cache miss detected via header {header}: {value}")
                    return True
            return False
        except Exception as e:
            logger.error(f"Error detecting cache miss: {str(e)}")
            return False

    def analyze_responses(self, responses: List[Dict[str, str]]) -> Dict[str, int]:
        """
        Analyze a list of response headers to count hits and misses.
        
        Args:
            responses (List[Dict[str, str]]): List of response headers
            
        Returns:
            Dict[str, int]: Counts of hits and misses
        """
        hits = 0
        misses = 0
        unknown = 0

        for headers in responses:
            if self.is_cache_hit(headers):
                hits += 1
            elif self.is_cache_miss(headers):
                misses += 1
            else:
                unknown += 1

        logger.info(f"Cache hit/miss analysis: {hits} hits, {misses} misses, {unknown} unknown")
        return {
            'hits': hits,
            'misses': misses,
            'unknown': unknown
        }

if __name__ == "__main__":
    # Example usage
    detector = CacheHitMissDetector()
    sample_headers = [
        {'X-Cache': 'HIT'},
        {'X-Cache': 'MISS'},
        {'CF-Cache-Status': 'HIT'},
        {'Age': '120'},
        {'X-Cache': 'MISS'},
        {}
    ]
    result = detector.analyze_responses(sample_headers)
    print(f"Cache hit/miss counts: {result}")
