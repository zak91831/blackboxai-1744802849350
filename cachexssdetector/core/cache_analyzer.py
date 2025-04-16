"""
Cache Behavior Analysis Engine for CacheXSSDetector.
Analyzes cache behavior patterns to identify potential vulnerabilities.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import asyncio
import time
import hashlib
from ..utils.logger import get_logger
from ..request.http_client import HTTPClient

logger = get_logger(__name__)

@dataclass
class CacheInfo:
    """Data class for storing cache analysis results."""
    is_cached: bool
    cache_headers: Dict[str, str]
    cache_control: Dict[str, str]
    ttl: Optional[int]
    vary_headers: List[str]
    cache_key_components: List[str]
    timestamp: str = datetime.now().isoformat()

class CacheAnalyzer:
    """
    Analyzes cache behavior of web applications to identify potential vulnerabilities.
    """

    def __init__(self):
        """Initialize Cache Analyzer with default settings."""
        self.cache_headers = [
            "X-Cache",
            "X-Cache-Hit",
            "CF-Cache-Status",
            "Age",
            "Cache-Control",
            "ETag",
            "Last-Modified",
            "Expires",
            "Vary"
        ]
        
        self.cache_control_directives = [
            "public",
            "private",
            "no-cache",
            "no-store",
            "max-age",
            "s-maxage",
            "must-revalidate",
            "proxy-revalidate",
            "immutable"
        ]

    async def analyze(self, client: HTTPClient, url: str) -> CacheInfo:
        """
        Analyze cache behavior for a given URL.
        
        Args:
            client (HTTPClient): HTTP client instance
            url (str): URL to analyze
            
        Returns:
            CacheInfo: Analysis results
        """
        try:
            # Perform initial request
            response1 = await client.get(url)
            headers1 = response1.headers
            
            # Extract cache headers
            cache_headers = self._extract_cache_headers(headers1)
            cache_control = self._parse_cache_control(headers1.get('Cache-Control', ''))
            vary_headers = self._parse_vary_headers(headers1.get('Vary', ''))
            
            # Determine if response is cacheable
            is_cached = self._is_response_cached(headers1)
            ttl = self._calculate_ttl(headers1)
            
            # Analyze cache key components
            cache_key_components = self._analyze_cache_key_components(headers1)
            
            # Perform cache validation tests
            await self._validate_cache_behavior(client, url, headers1)
            
            return CacheInfo(
                is_cached=is_cached,
                cache_headers=cache_headers,
                cache_control=cache_control,
                ttl=ttl,
                vary_headers=vary_headers,
                cache_key_components=cache_key_components
            )
            
        except Exception as e:
            logger.error(f"Cache analysis failed for {url}: {str(e)}")
            return CacheInfo(
                is_cached=False,
                cache_headers={},
                cache_control={},
                ttl=None,
                vary_headers=[],
                cache_key_components=[]
            )

    def _extract_cache_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Extract relevant cache-related headers.
        
        Args:
            headers (Dict[str, str]): Response headers
            
        Returns:
            Dict[str, str]: Cache-related headers
        """
        return {
            header: headers[header]
            for header in self.cache_headers
            if header in headers
        }

    def _parse_cache_control(self, cache_control: str) -> Dict[str, str]:
        """
        Parse Cache-Control header into components.
        
        Args:
            cache_control (str): Cache-Control header value
            
        Returns:
            Dict[str, str]: Parsed cache control directives
        """
        directives = {}
        
        if not cache_control:
            return directives
            
        parts = [p.strip() for p in cache_control.split(',')]
        
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                directives[key.strip()] = value.strip()
            else:
                directives[part.strip()] = True
                
        return directives

    def _parse_vary_headers(self, vary: str) -> List[str]:
        """
        Parse Vary header into components.
        
        Args:
            vary (str): Vary header value
            
        Returns:
            List[str]: List of varying headers
        """
        if not vary:
            return []
            
        return [h.strip() for h in vary.split(',')]

    def _is_response_cached(self, headers: Dict[str, str]) -> bool:
        """
        Determine if a response is cached based on headers.
        
        Args:
            headers (Dict[str, str]): Response headers
            
        Returns:
            bool: True if response appears to be cached
        """
        # Check explicit cache indicators
        if 'X-Cache' in headers and 'HIT' in headers['X-Cache'].upper():
            return True
            
        if 'CF-Cache-Status' in headers and 'HIT' in headers['CF-Cache-Status'].upper():
            return True
            
        # Check Cache-Control
        cache_control = headers.get('Cache-Control', '')
        if 'no-store' in cache_control or 'no-cache' in cache_control:
            return False
            
        # Check for other caching indicators
        if 'Age' in headers or 'ETag' in headers or 'Last-Modified' in headers:
            return True
            
        return False

    def _calculate_ttl(self, headers: Dict[str, str]) -> Optional[int]:
        """
        Calculate Time-To-Live for cached content.
        
        Args:
            headers (Dict[str, str]): Response headers
            
        Returns:
            Optional[int]: TTL in seconds, or None if not determinable
        """
        try:
            # Check Cache-Control max-age
            cache_control = self._parse_cache_control(headers.get('Cache-Control', ''))
            if 'max-age' in cache_control:
                return int(cache_control['max-age'])
                
            # Check Expires header
            if 'Expires' in headers:
                expires = datetime.strptime(headers['Expires'], '%a, %d %b %Y %H:%M:%S %Z')
                now = datetime.utcnow()
                return int((expires - now).total_seconds())
                
            return None
            
        except Exception as e:
            logger.error(f"Error calculating TTL: {str(e)}")
            return None

    def _analyze_cache_key_components(self, headers: Dict[str, str]) -> List[str]:
        """
        Analyze which components are likely part of the cache key.
        
        Args:
            headers (Dict[str, str]): Response headers
            
        Returns:
            List[str]: List of probable cache key components
        """
        components = []
        
        # Check Vary header
        vary = headers.get('Vary', '')
        if vary:
            components.extend(self._parse_vary_headers(vary))
            
        # Add common cache key components
        components.extend([
            'URL',
            'Method',
            'Protocol'
        ])
        
        # Check for CDN-specific headers
        if any(h.startswith(('CF-', 'X-Cache-')) for h in headers):
            components.append('CDN-Specific')
            
        return components

    async def _validate_cache_behavior(
        self,
        client: HTTPClient,
        url: str,
        initial_headers: Dict[str, str]
    ) -> None:
        """
        Perform additional tests to validate cache behavior.
        
        Args:
            client (HTTPClient): HTTP client instance
            url (str): URL to test
            initial_headers (Dict[str, str]): Headers from initial request
        """
        try:
            # Test with different headers
            variations = [
                {'User-Agent': 'CacheTest/1.0'},
                {'Accept': 'text/plain'},
                {'Accept-Encoding': 'identity'}
            ]
            
            for headers in variations:
                response = await client.get(url, headers=headers)
                self._compare_cache_behavior(initial_headers, response.headers)
                
            # Test with rapid requests
            await self._test_rapid_requests(client, url)
            
        except Exception as e:
            logger.error(f"Cache validation failed: {str(e)}")

    def _compare_cache_behavior(
        self,
        headers1: Dict[str, str],
        headers2: Dict[str, str]
    ) -> None:
        """
        Compare cache behavior between two responses.
        
        Args:
            headers1 (Dict[str, str]): Headers from first response
            headers2 (Dict[str, str]): Headers from second response
        """
        try:
            # Compare cache indicators
            cache1 = self._extract_cache_headers(headers1)
            cache2 = self._extract_cache_headers(headers2)
            
            if cache1 != cache2:
                logger.info("Different cache behavior detected between requests")
                logger.debug(f"Cache1: {cache1}")
                logger.debug(f"Cache2: {cache2}")
                
        except Exception as e:
            logger.error(f"Error comparing cache behavior: {str(e)}")

    async def _test_rapid_requests(self, client: HTTPClient, url: str) -> None:
        """
        Test cache behavior with rapid successive requests.
        
        Args:
            client (HTTPClient): HTTP client instance
            url (str): URL to test
        """
        try:
            # Make multiple rapid requests
            responses = await asyncio.gather(
                *[client.get(url) for _ in range(3)],
                return_exceptions=True
            )
            
            # Analyze responses
            cache_hits = sum(
                1 for r in responses
                if isinstance(r, Exception) or self._is_response_cached(r.headers)
            )
            
            if cache_hits > 0:
                logger.info(f"Detected {cache_hits} cache hits in rapid requests")
                
        except Exception as e:
            logger.error(f"Error testing rapid requests: {str(e)}")

    def generate_cache_buster(self, url: str) -> str:
        """
        Generate a cache-busting URL variation.
        
        Args:
            url (str): Original URL
            
        Returns:
            str: URL with cache-busting parameter
        """
        timestamp = int(time.time())
        random_component = hashlib.md5(str(timestamp).encode()).hexdigest()[:8]
        
        separator = '&' if '?' in url else '?'
        return f"{url}{separator}_={timestamp}-{random_component}"

if __name__ == "__main__":
    # Test cache analyzer functionality
    async def test_analyzer():
        client = HTTPClient()
        analyzer = CacheAnalyzer()
        result = await analyzer.analyze(client, "http://example.com")
        print(f"Cache Analysis Result: {result}")
        
    asyncio.run(test_analyzer())
