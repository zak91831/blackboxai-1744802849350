"""
HTTP Client with Cookie/Session Support for CacheXSSDetector.
Handles HTTP requests with advanced features like session management and proxy support.
"""

import aiohttp
import asyncio
from typing import Dict, Optional, Union, Any
import json
from urllib.parse import urlparse
import ssl
import certifi
from ..utils.logger import get_logger

logger = get_logger(__name__)

class HTTPClient:
    """
    Asynchronous HTTP client with advanced features for security testing.
    """

    def __init__(
        self,
        timeout: int = 30,
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
        max_retries: int = 3,
        follow_redirects: bool = True
    ):
        """
        Initialize HTTP client with configuration.
        
        Args:
            timeout (int): Request timeout in seconds
            proxy (Optional[str]): Proxy URL
            verify_ssl (bool): Whether to verify SSL certificates
            max_retries (int): Maximum number of retry attempts
            follow_redirects (bool): Whether to follow redirects
        """
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        self.follow_redirects = follow_redirects
        
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
        
        # Session storage
        self.sessions: Dict[str, aiohttp.ClientSession] = {}

    async def get_session(self, url: str) -> aiohttp.ClientSession:
        """
        Get or create a session for a given URL.
        
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
            
            # Create new session with custom configuration
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.sessions[hostname] = aiohttp.ClientSession(
                timeout=timeout,
                headers=self.default_headers.copy(),
                trust_env=True,
                connector=aiohttp.TCPConnector(
                    ssl=ssl_context,
                    force_close=True
                )
            )
            
        return self.sessions[hostname]

    async def close_all_sessions(self):
        """Close all active sessions."""
        for session in self.sessions.values():
            if not session.closed:
                await session.close()
        self.sessions.clear()

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
        cancel_event: Optional[asyncio.Event] = None
    ) -> aiohttp.ClientResponse:
        """
        Send an HTTP request with retry logic and optional cancellation.
        
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
            
        Returns:
            aiohttp.ClientResponse: Response object
        """
        if allow_redirects is None:
            allow_redirects = self.follow_redirects

        # Merge headers with defaults
        request_headers = self.default_headers.copy()
        if headers:
            request_headers.update(headers)

        # Configure proxy if specified
        proxy_settings = {}
        if self.proxy:
            proxy_settings['proxy'] = self.proxy

        retries = 0
        last_exception = None

        while retries <= self.max_retries:
            try:
                session = await self.get_session(url)
                
                # Use asyncio.wait_for to apply timeout and cancellation
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
                        response = await asyncio.wait_for(make_request(), timeout=timeout)
                    else:
                        response = await make_request()

                return response

            except asyncio.CancelledError:
                logger.warning("Request was cancelled")
                raise

            except asyncio.TimeoutError:
                last_exception = asyncio.TimeoutError("Request timed out")
                retries += 1
                if retries <= self.max_retries:
                    wait_time = 2 ** retries
                    logger.warning(f"Request timed out (attempt {retries}/{self.max_retries}), retrying in {wait_time}s")
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"Request timed out after {self.max_retries} retries")
                    raise last_exception

            except aiohttp.ClientError as e:
                last_exception = e
                retries += 1
                
                if retries <= self.max_retries:
                    wait_time = 2 ** retries  # Exponential backoff
                    logger.warning(
                        f"Request failed (attempt {retries}/{self.max_retries}), "
                        f"retrying in {wait_time}s: {str(e)}"
                    )
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"Request failed after {self.max_retries} retries: {str(e)}")
                    raise

            except Exception as e:
                logger.error(f"Unexpected error during request: {str(e)}")
                raise

        raise last_exception or Exception("Request failed for unknown reason")

    async def get(
        self,
        url: str,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """
        Send GET request.
        
        Args:
            url (str): Target URL
            **kwargs: Additional arguments for request method
            
        Returns:
            aiohttp.ClientResponse: Response object
        """
        return await self.request('GET', url, **kwargs)

    async def post(
        self,
        url: str,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """
        Send POST request.
        
        Args:
            url (str): Target URL
            **kwargs: Additional arguments for request method
            
        Returns:
            aiohttp.ClientResponse: Response object
        """
        return await self.request('POST', url, **kwargs)

    async def head(
        self,
        url: str,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """
        Send HEAD request.
        
        Args:
            url (str): Target URL
            **kwargs: Additional arguments for request method
            
        Returns:
            aiohttp.ClientResponse: Response object
        """
        return await self.request('HEAD', url, **kwargs)

    async def options(
        self,
        url: str,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """
        Send OPTIONS request.
        
        Args:
            url (str): Target URL
            **kwargs: Additional arguments for request method
            
        Returns:
            aiohttp.ClientResponse: Response object
        """
        return await self.request('OPTIONS', url, **kwargs)

    async def check_cache_headers(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Check cache-related headers for a URL.
        
        Args:
            url (str): URL to check
            headers (Optional[Dict[str, str]]): Additional headers
            
        Returns:
            Dict[str, Any]: Cache header analysis
        """
        try:
            response = await self.head(url, headers=headers)
            
            cache_info = {
                'cacheable': False,
                'cache_control': response.headers.get('Cache-Control', ''),
                'etag': response.headers.get('ETag'),
                'last_modified': response.headers.get('Last-Modified'),
                'expires': response.headers.get('Expires'),
                'vary': response.headers.get('Vary'),
                'x_cache': response.headers.get('X-Cache'),
                'age': response.headers.get('Age')
            }
            
            # Determine if response is cacheable
            cache_control = cache_info['cache_control'].lower()
            cache_info['cacheable'] = (
                'public' in cache_control or
                'max-age' in cache_control or
                cache_info['etag'] is not None or
                cache_info['last_modified'] is not None
            )
            
            return cache_info
            
        except Exception as e:
            logger.error(f"Error checking cache headers: {str(e)}")
            return {'error': str(e)}

    async def test_cache_behavior(
        self,
        url: str,
        test_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Test cache behavior with multiple requests.
        
        Args:
            url (str): URL to test
            test_headers (Optional[Dict[str, str]]): Headers to test with
            
        Returns:
            Dict[str, Any]: Cache behavior analysis
        """
        try:
            results = {
                'consistent_caching': False,
                'varies_by_headers': False,
                'cache_hits': 0,
                'total_requests': 3
            }
            
            # Make multiple requests
            responses = []
            for _ in range(3):
                response = await self.get(url, headers=test_headers)
                responses.append({
                    'status': response.status,
                    'headers': dict(response.headers),
                    'cache_hit': 'HIT' in response.headers.get('X-Cache', '').upper()
                })
                
                if responses[-1]['cache_hit']:
                    results['cache_hits'] += 1
                    
                await asyncio.sleep(1)  # Delay between requests
            
            # Analyze consistency
            results['consistent_caching'] = all(
                r['cache_hit'] == responses[0]['cache_hit']
                for r in responses[1:]
            )
            
            # Check header variation
            if test_headers:
                control_response = await self.get(url)
                results['varies_by_headers'] = any(
                    control_response.headers.get(h) != responses[0]['headers'].get(h)
                    for h in ['ETag', 'Last-Modified']
                )
            
            return results
            
        except Exception as e:
            logger.error(f"Error testing cache behavior: {str(e)}")
            return {'error': str(e)}

if __name__ == "__main__":
    # Test HTTP client functionality
    async def test_client():
        client = HTTPClient()
        try:
            response = await client.get("http://example.com")
            print(f"Status: {response.status}")
            print(f"Headers: {response.headers}")
        finally:
            await client.close_all_sessions()
    
    asyncio.run(test_client())
