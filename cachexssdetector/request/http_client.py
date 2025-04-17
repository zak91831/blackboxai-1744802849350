"""
Enhanced HTTP Client with Connection Pooling and Concurrency Control.
Optimized for performance and reliability in security testing scenarios.
"""

import aiohttp
import asyncio
from typing import Dict, Optional, Union, Any, Set
import json
from urllib.parse import urlparse
import ssl
import certifi
from ..utils.logger import get_logger
from functools import lru_cache

logger = get_logger(__name__)

class HTTPClient:
    """
    Optimized asynchronous HTTP client with connection pooling and concurrency control.
    """

    def __init__(
        self,
        timeout: int = 30,
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
        max_retries: int = 3,
        follow_redirects: bool = True,
        max_connections: int = 100,
        max_connections_per_host: int = 10,
        response_cache_size: int = 1000
    ):
        """
        Initialize HTTP client with optimized configuration.
        
        Args:
            timeout (int): Request timeout in seconds
            proxy (Optional[str]): Proxy URL
            verify_ssl (bool): Whether to verify SSL certificates
            max_retries (int): Maximum number of retry attempts
            follow_redirects (bool): Whether to follow redirects
            max_connections (int): Maximum total concurrent connections
            max_connections_per_host (int): Maximum concurrent connections per host
            response_cache_size (int): Size of LRU cache for responses
        """
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        self.follow_redirects = follow_redirects
        self.max_connections = max_connections
        self.max_connections_per_host = max_connections_per_host
        
        # Connection semaphores
        self._connection_semaphore = asyncio.Semaphore(max_connections)
        self._host_semaphores: Dict[str, asyncio.Semaphore] = {}
        
        # Default headers
        self.default_headers = {
            'User-Agent': 'CacheXSSDetector/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        # Session and connection tracking
        self.sessions: Dict[str, aiohttp.ClientSession] = {}
        self._active_requests: Set[str] = set()
        
        # Response caching
        self._response_cache = {}
        self._response_cache_size = response_cache_size

    def _generate_cache_key(self, method: str, url: str, headers: Optional[Dict] = None) -> str:
        """Generate cache key for request."""
        key_parts = [method, url]
        if headers:
            # Sort headers to ensure consistent cache keys
            sorted_headers = sorted(
                (k.lower(), v) for k, v in headers.items()
                if k.lower() not in {'cache-control', 'pragma', 'cookie'}
            )
            key_parts.extend(f"{k}:{v}" for k, v in sorted_headers)
        return "|".join(key_parts)

    def _get_cached_response(self, cache_key: str) -> Optional[aiohttp.ClientResponse]:
        """Get cached response."""
        return self._response_cache.get(cache_key)

    def _cache_response(self, cache_key: str, response: aiohttp.ClientResponse) -> None:
        """Cache response with LRU eviction."""
        if len(self._response_cache) >= self._response_cache_size:
            # Remove oldest entry
            oldest_key = next(iter(self._response_cache))
            del self._response_cache[oldest_key]
        self._response_cache[cache_key] = response

    async def _get_host_semaphore(self, hostname: str) -> asyncio.Semaphore:
        """Get or create a semaphore for a specific hostname."""
        if hostname not in self._host_semaphores:
            self._host_semaphores[hostname] = asyncio.Semaphore(
                self.max_connections_per_host
            )
        return self._host_semaphores[hostname]

    async def get_session(self, url: str) -> aiohttp.ClientSession:
        """
        Get or create an optimized session for a given URL.
        
        Args:
            url (str): URL to create session for
            
        Returns:
            aiohttp.ClientSession: Session object
        """
        hostname = urlparse(url).netloc
        
        if hostname not in self.sessions:
            # SSL context configuration
            if self.verify_ssl:
                ssl_context = ssl.create_default_context(cafile=certifi.where())
            else:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            
            # Create TCP connector with optimized settings
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit_per_host=self.max_connections_per_host,
                force_close=False,  # Allow connection pooling
                enable_cleanup_closed=True,
                keepalive_timeout=30
            )
            
            # Create new session with optimized configuration
            timeout = aiohttp.ClientTimeout(
                total=self.timeout,
                connect=10,
                sock_read=self.timeout
            )
            
            self.sessions[hostname] = aiohttp.ClientSession(
                timeout=timeout,
                headers=self.default_headers.copy(),
                connector=connector,
                trust_env=True
            )
            
        return self.sessions[hostname]

    async def close_all_sessions(self):
        """Close all active sessions and clean up resources."""
        for session in self.sessions.values():
            if not session.closed:
                await session.close()
        self.sessions.clear()
        self._host_semaphores.clear()
        self._active_requests.clear()

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Union[Dict[str, Any], str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        cookies: Optional[Dict[str, str]] = None,
        allow_redirects: Optional[bool] = None,
        timeout: Optional[float] = None,
        cancel_event: Optional[asyncio.Event] = None,
        use_cache: bool = True
    ) -> aiohttp.ClientResponse:
        """
        Send an HTTP request with optimized retry logic and resource management.
        
        Args:
            method (str): HTTP method
            url (str): Target URL
            headers (Optional[Dict[str, str]]): Request headers
            params (Optional[Dict[str, str]]): URL parameters
            data (Optional[Union[Dict[str, Any], str]]): Request data
            json_data (Optional[Dict[str, Any]]): JSON request data
            cookies (Optional[Dict[str, str]]): Request cookies
            allow_redirects (Optional[bool]): Whether to follow redirects
            timeout (Optional[float]): Timeout in seconds for the request
            cancel_event (Optional[asyncio.Event]): Event to signal cancellation
            use_cache (bool): Whether to use response caching
            
        Returns:
            aiohttp.ClientResponse: Response object
        """
        if allow_redirects is None:
            allow_redirects = self.follow_redirects

        # Merge headers with defaults
        request_headers = self.default_headers.copy()
        if headers:
            request_headers.update(headers)

            # Check cache if enabled
            if use_cache and method.upper() == 'GET':
                cache_key = self._generate_cache_key(method, url, request_headers)
                if cached_response := self._get_cached_response(cache_key):
                    logger.debug(f"Cache hit for {url}")
                    return cached_response

        # Configure proxy if specified
        proxy_settings = {}
        if self.proxy:
            proxy_settings['proxy'] = self.proxy

        hostname = urlparse(url).netloc
        host_semaphore = await self._get_host_semaphore(hostname)
        
        retries = 0
        last_exception = None
        request_id = f"{method}:{url}"

        while retries <= self.max_retries:
            try:
                # Acquire connection semaphores
                async with self._connection_semaphore:
                    async with host_semaphore:
                        if request_id in self._active_requests:
                            logger.warning(f"Duplicate request detected: {request_id}")
                            await asyncio.sleep(1)
                            continue
                            
                        self._active_requests.add(request_id)
                        try:
                            session = await self.get_session(url)
                            
                            # Use asyncio.wait_for for timeout control
                            async def make_request():
                                async with session.request(
                                    method=method,
                                    url=url,
                                    headers=request_headers,
                                    params=params,
                                    data=data,
                                    json=json_data,
                                    cookies=cookies,
                                    allow_redirects=allow_redirects,
                                    **proxy_settings
                                ) as response:
                                    # Read response data to ensure connection is properly closed
                                    await response.read()
                                    return response

                            if cancel_event:
                                done, pending = await asyncio.wait(
                                    [make_request(), cancel_event.wait()],
                                    return_when=asyncio.FIRST_COMPLETED
                                )
                                if cancel_event.is_set():
                                    for task in pending:
                                        task.cancel()
                                    raise asyncio.CancelledError("Request cancelled")
                                response = done.pop().result()
                            else:
                                if timeout:
                                    response = await asyncio.wait_for(
                                        make_request(),
                                        timeout=timeout
                                    )
                                else:
                                    response = await make_request()

                            # Cache successful GET responses
                            if use_cache and method.upper() == 'GET':
                                cache_key = self._generate_cache_key(method, url, request_headers)
                                self._cache_response(cache_key, response)

                            return response

                        finally:
                            self._active_requests.remove(request_id)

            except asyncio.CancelledError:
                logger.warning(f"Request cancelled: {url}")
                raise

            except asyncio.TimeoutError:
                last_exception = asyncio.TimeoutError(
                    f"Request timed out after {timeout or self.timeout}s"
                )
                retries += 1
                if retries <= self.max_retries:
                    wait_time = min(2 ** retries, 30)  # Cap maximum wait time
                    logger.warning(
                        f"Request timed out (attempt {retries}/{self.max_retries}), "
                        f"retrying in {wait_time}s: {url}"
                    )
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"Request timed out after {self.max_retries} retries: {url}")
                    raise last_exception

            except aiohttp.ClientError as e:
                last_exception = e
                retries += 1
                
                if retries <= self.max_retries:
                    wait_time = min(2 ** retries, 30)  # Cap maximum wait time
                    logger.warning(
                        f"Request failed (attempt {retries}/{self.max_retries}), "
                        f"retrying in {wait_time}s: {url} - {str(e)}"
                    )
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"Request failed after {self.max_retries} retries: {url} - {str(e)}")
                    raise

            except Exception as e:
                logger.error(f"Unexpected error during request to {url}: {str(e)}")
                raise

        raise last_exception or Exception(f"Request failed for unknown reason: {url}")

    async def get(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Send GET request."""
        return await self.request('GET', url, **kwargs)

    async def post(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Send POST request."""
        return await self.request('POST', url, **kwargs)

    async def head(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Send HEAD request."""
        return await self.request('HEAD', url, **kwargs)

    async def options(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Send OPTIONS request."""
        return await self.request('OPTIONS', url, **kwargs)

    async def check_cache_headers(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Check cache-related headers with optimized request handling.
        
        Args:
            url (str): URL to check
            headers (Optional[Dict[str, str]]): Additional headers
            
        Returns:
            Dict[str, Any]: Cache header analysis
        """
        try:
            response = await self.head(
                url,
                headers=headers,
                use_cache=False  # Don't cache HEAD requests
            )
            
            cache_info = {
                'cacheable': False,
                'cache_control': response.headers.get('Cache-Control', ''),
                'etag': response.headers.get('ETag'),
                'last_modified': response.headers.get('Last-Modified'),
                'expires': response.headers.get('Expires'),
                'vary': response.headers.get('Vary'),
                'x_cache': response.headers.get('X-Cache'),
                'age': response.headers.get('Age'),
                'status_code': response.status
            }
            
            # Enhanced cache analysis
            cache_control = cache_info['cache_control'].lower()
            cache_info['cacheable'] = (
                'public' in cache_control or
                'max-age' in cache_control or
                'must-revalidate' in cache_control or
                cache_info['etag'] is not None or
                cache_info['last_modified'] is not None or
                cache_info['expires'] is not None
            )
            
            # Additional cache indicators
            cache_info['cache_hints'] = {
                'has_etag': bool(cache_info['etag']),
                'has_last_modified': bool(cache_info['last_modified']),
                'has_vary': bool(cache_info['vary']),
                'has_age': bool(cache_info['age']),
                'no_store': 'no-store' in cache_control,
                'no_cache': 'no-cache' in cache_control,
                'private': 'private' in cache_control
            }
            
            return cache_info
            
        except Exception as e:
            logger.error(f"Error checking cache headers for {url}: {str(e)}")
            return {
                'error': str(e),
                'cacheable': False,
                'status_code': None
            }

    async def test_cache_behavior(
        self,
        url: str,
        test_headers: Optional[Dict[str, str]] = None,
        samples: int = 3,
        delay: float = 1.0
    ) -> Dict[str, Any]:
        """
        Test cache behavior with optimized multiple requests.
        
        Args:
            url (str): URL to test
            test_headers (Optional[Dict[str, str]]): Headers to test with
            samples (int): Number of requests to make
            delay (float): Delay between requests in seconds
            
        Returns:
            Dict[str, Any]: Cache behavior analysis
        """
        try:
            results = {
                'consistent_caching': False,
                'varies_by_headers': False,
                'cache_hits': 0,
                'total_requests': samples,
                'response_times': [],
                'status_codes': set(),
                'etag_consistent': True,
                'last_modified_consistent': True
            }
            
            # Make multiple requests
            responses = []
            for i in range(samples):
                start_time = asyncio.get_event_loop().time()
                response = await self.get(
                    url,
                    headers=test_headers,
                    use_cache=False  # Disable response caching for this test
                )
                end_time = asyncio.get_event_loop().time()
                
                response_data = {
                    'status': response.status,
                    'headers': dict(response.headers),
                    'response_time': end_time - start_time,
                    'cache_hit': 'HIT' in response.headers.get('X-Cache', '').upper()
                }
                
                responses.append(response_data)
                results['response_times'].append(response_data['response_time'])
                results['status_codes'].add(response_data['status'])
                
                if response_data['cache_hit']:
                    results['cache_hits'] += 1
                    
                if i < samples - 1:
                    await asyncio.sleep(delay)
            
            # Analyze results
            results['consistent_caching'] = all(
                r['cache_hit'] == responses[0]['cache_hit']
                for r in responses[1:]
            )
            
            # Check header consistency
            if len(responses) > 1:
                first_etag = responses[0]['headers'].get('ETag')
                first_modified = responses[0]['headers'].get('Last-Modified')
                
                results['etag_consistent'] = all(
                    r['headers'].get('ETag') == first_etag
                    for r in responses[1:]
                )
                
                results['last_modified_consistent'] = all(
                    r['headers'].get('Last-Modified') == first_modified
                    for r in responses[1:]
                )
            
            # Add timing statistics
            results['timing'] = {
                'min': min(results['response_times']),
                'max': max(results['response_times']),
                'avg': sum(results['response_times']) / len(results['response_times'])
            }
            
            return results
            
        except Exception as e:
            logger.error(f"Error testing cache behavior for {url}: {str(e)}")
            return {'error': str(e)}

if __name__ == "__main__":
    # Test HTTP client functionality
    async def test_client():
        client = HTTPClient(
            max_connections=50,
            max_connections_per_host=5
        )
        try:
            response = await client.get("http://example.com")
            print(f"Status: {response.status}")
            print(f"Headers: {response.headers}")
            
            # Test cache behavior
            cache_info = await client.check_cache_headers("http://example.com")
            print(f"Cache Info: {json.dumps(cache_info, indent=2)}")
            
        finally:
            await client.close_all_sessions()
    
    asyncio.run(test_client())
