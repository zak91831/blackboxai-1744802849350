"""
Enhanced Cache Behavior Analysis Engine for CacheXSSDetector.
Optimized analyzer with improved performance and reliability.
"""

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
import asyncio
import time
import hashlib
from functools import lru_cache
from ..utils.logger import get_logger
from ..request.http_client import HTTPClient

logger = get_logger(__name__)

@dataclass(frozen=True)
class CacheInfo:
    """Enhanced data class for storing cache analysis results."""
    is_cached: bool
    cache_headers: Tuple[Tuple[str, str], ...]
    cache_control: Tuple[Tuple[str, str], ...]
    ttl: Optional[int]
    vary_headers: Tuple[str, ...]
    cache_key_components: Tuple[str, ...]
    timestamp: str = datetime.now().isoformat()
    response_time: Optional[float] = None
    status_code: Optional[int] = None
    cache_hit_ratio: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert cache info to dictionary."""
        return asdict(self)

class CacheAnalyzer:
    """
    Optimized cache behavior analyzer with improved performance and reliability.
    """

    def __init__(self, cache_size: int = 1000):
        """
        Initialize Cache Analyzer with optimized settings.
        
        Args:
            cache_size (int): Size of LRU cache for analysis results
        """
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
        
        # Initialize cache and concurrency control
        self._cache = {}
        self._cache_size = cache_size
        self._analysis_semaphore = asyncio.Semaphore(10)

    def _create_immutable_dict(self, d: Dict) -> Tuple[Tuple[str, str], ...]:
        """Convert dictionary to immutable tuple of tuples."""
        return tuple(sorted((str(k), str(v)) for k, v in d.items()))

    async def analyze(self, client: HTTPClient, url: str) -> CacheInfo:
        """
        Analyze cache behavior with optimized request handling.
        
        Args:
            client (HTTPClient): HTTP client instance
            url (str): URL to analyze
            
        Returns:
            CacheInfo: Analysis results
        """
        try:
            async with self._analysis_semaphore:
                start_time = time.time()
                
                # Check cache first
                cache_key = self._generate_cache_key(url)
                if cached_result := self._get_cached_result(cache_key):
                    logger.debug(f"Cache hit for analysis of {url}")
                    return cached_result
                
                # Perform initial request with timing
                response = await client.get(
                    url,
                    headers={'Cache-Control': 'no-cache'},
                    use_cache=False
                )
                
                response_time = time.time() - start_time
                
                # Extract and analyze headers
                headers = dict(response.headers)
                cache_headers = self._extract_cache_headers(headers)
                cache_control = self._parse_cache_control(headers.get('Cache-Control', ''))
                vary_headers = self._parse_vary_headers(headers.get('Vary', ''))
                
                # Determine cacheability
                is_cached = self._is_response_cached(headers)
                ttl = self._calculate_ttl(headers)
                
                # Analyze cache key components
                cache_key_components = self._analyze_cache_key_components(headers)
                
                # Perform quick cache validation
                cache_hit_ratio = await self._quick_cache_check(client, url)
                
                # Convert dictionaries to immutable types
                immutable_cache_headers = self._create_immutable_dict(cache_headers)
                immutable_cache_control = self._create_immutable_dict(cache_control)
                immutable_vary_headers = tuple(sorted(vary_headers))
                immutable_cache_key_components = tuple(sorted(cache_key_components))
                
                result = CacheInfo(
                    is_cached=is_cached,
                    cache_headers=immutable_cache_headers,
                    cache_control=immutable_cache_control,
                    ttl=ttl,
                    vary_headers=immutable_vary_headers,
                    cache_key_components=immutable_cache_key_components,
                    response_time=response_time,
                    status_code=response.status,
                    cache_hit_ratio=cache_hit_ratio
                )
                
                # Cache the result
                self._cache_result(cache_key, result)
                
                return result
                
        except Exception as e:
            logger.error(f"Cache analysis failed for {url}: {str(e)}")
            return CacheInfo(
                is_cached=False,
                cache_headers=(),
                cache_control=(),
                ttl=None,
                vary_headers=(),
                cache_key_components=(),
                status_code=None,
                cache_hit_ratio=0.0
            )

    def _generate_cache_key(self, url: str) -> str:
        """Generate a unique cache key for analysis results."""
        return hashlib.md5(url.encode()).hexdigest()

    def _get_cached_result(self, cache_key: str) -> Optional[CacheInfo]:
        """Get cached analysis result."""
        return self._cache.get(cache_key)

    def _cache_result(self, cache_key: str, result: CacheInfo) -> None:
        """Cache analysis result with LRU eviction."""
        if len(self._cache) >= self._cache_size:
            # Remove oldest entry
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
        self._cache[cache_key] = result

    def _extract_cache_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract cache-related headers efficiently."""
        return {
            header: headers[header]
            for header in self.cache_headers
            if header in headers
        }

    def _parse_cache_control(self, cache_control: str) -> Dict[str, str]:
        """Parse Cache-Control header with improved handling."""
        directives = {}
        
        if not cache_control:
            return directives
            
        parts = [p.strip() for p in cache_control.split(',')]
        
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                directives[key.strip().lower()] = value.strip()
            else:
                directives[part.strip().lower()] = True
                
        return directives

    def _parse_vary_headers(self, vary: str) -> List[str]:
        """Parse Vary header with normalization."""
        if not vary:
            return []
            
        return [h.strip().lower() for h in vary.split(',')]

    def _is_response_cached(self, headers: Dict[str, str]) -> bool:
        """Enhanced cache detection logic."""
        # Check explicit cache indicators
        cache_status = headers.get('X-Cache', '').upper()
        if 'HIT' in cache_status or 'MISS' in cache_status:
            return 'HIT' in cache_status
            
        cdn_status = headers.get('CF-Cache-Status', '').upper()
        if cdn_status:
            return cdn_status == 'HIT'
            
        # Check Cache-Control
        cache_control = self._parse_cache_control(headers.get('Cache-Control', ''))
        if cache_control.get('no-store') or cache_control.get('no-cache'):
            return False
            
        # Check for caching indicators
        if (
            'Age' in headers or
            'ETag' in headers or
            'Last-Modified' in headers or
            cache_control.get('max-age') or
            cache_control.get('s-maxage')
        ):
            return True
            
        return False

    def _calculate_ttl(self, headers: Dict[str, str]) -> Optional[int]:
        """Calculate TTL with improved accuracy."""
        try:
            cache_control = self._parse_cache_control(headers.get('Cache-Control', ''))
            
            # Check max-age and s-maxage
            if 's-maxage' in cache_control:
                return int(cache_control['s-maxage'])
            if 'max-age' in cache_control:
                return int(cache_control['max-age'])
                
            # Check Age and Expires headers
            if 'Age' in headers and 'Expires' in headers:
                age = int(headers['Age'])
                expires = datetime.strptime(
                    headers['Expires'],
                    '%a, %d %b %Y %H:%M:%S %Z'
                )
                now = datetime.utcnow()
                return max(0, int((expires - now).total_seconds()) - age)
                
            return None
            
        except Exception as e:
            logger.error(f"Error calculating TTL: {str(e)}")
            return None

    def _analyze_cache_key_components(self, headers: Dict[str, str]) -> List[str]:
        """Analyze cache key components with CDN detection."""
        components = ['URL', 'Method']
        
        # Add Vary header components
        vary_headers = self._parse_vary_headers(headers.get('Vary', ''))
        if vary_headers:
            components.extend(vary_headers)
        
        # Detect CDN-specific components
        if any(k.startswith(('CF-', 'X-Cache-', 'Fastly-', 'Akamai-')) for k in headers):
            components.append('CDN-Specific')
            
        # Add cache control specific components
        cache_control = self._parse_cache_control(headers.get('Cache-Control', ''))
        if cache_control:
            if cache_control.get('private'):
                components.append('Private')
            if cache_control.get('vary-by-cookie'):
                components.append('Cookie')
                
        return list(set(components))  # Remove duplicates

    async def _quick_cache_check(
        self,
        client: HTTPClient,
        url: str,
        samples: int = 3
    ) -> float:
        """
        Perform quick cache behavior check.
        
        Args:
            client (HTTPClient): HTTP client instance
            url (str): URL to test
            samples (int): Number of requests to make
            
        Returns:
            float: Cache hit ratio
        """
        try:
            hits = 0
            
            # Make multiple rapid requests
            for _ in range(samples):
                response = await client.get(url, use_cache=False)
                if self._is_response_cached(dict(response.headers)):
                    hits += 1
                await asyncio.sleep(0.1)  # Small delay between requests
                
            return hits / samples
            
        except Exception as e:
            logger.error(f"Error in quick cache check: {str(e)}")
            return 0.0

    def generate_cache_buster(self, url: str) -> str:
        """
        Generate an effective cache-busting URL.
        
        Args:
            url (str): Original URL
            
        Returns:
            str: URL with cache-busting parameter
        """
        timestamp = int(time.time() * 1000)  # Millisecond precision
        random_component = hashlib.md5(str(timestamp).encode()).hexdigest()[:8]
        
        separator = '&' if '?' in url else '?'
        return f"{url}{separator}_cb={timestamp}-{random_component}"

if __name__ == "__main__":
    # Test cache analyzer functionality
    async def test_analyzer():
        client = HTTPClient()
        analyzer = CacheAnalyzer()
        try:
            result = await analyzer.analyze(client, "http://example.com")
            print(f"Cache Analysis Result:")
            print(f"Is Cached: {result.is_cached}")
            print(f"TTL: {result.ttl}")
            print(f"Cache Headers: {result.cache_headers}")
            print(f"Cache Hit Ratio: {result.cache_hit_ratio}")
        finally:
            await client.close_all_sessions()
        
    asyncio.run(test_analyzer())
