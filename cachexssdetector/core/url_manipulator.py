"""
Optimized URL Path Manipulation Module for CacheXSSDetector.
Handles efficient generation and manipulation of URL paths for testing cache-based XSS vulnerabilities.
"""

from typing import List, Set, Generator, Dict, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
import itertools
from ..utils.logger import get_logger
from functools import lru_cache

logger = get_logger(__name__)

class URLManipulator:
    """
    Optimized URL manipulation with smart variation generation and caching.
    """
    
    def __init__(self, max_variations: int = 100):
        """
        Initialize URL Manipulator with optimized test patterns.
        
        Args:
            max_variations (int): Maximum number of variations to generate per URL
        """
        self.max_variations = max_variations
        
        # Optimized path patterns focusing on cache-relevant variations
        self.path_patterns = [
            "/",
            "/*",
            "/*/",
            "//",
            "/./",
            "%2f",
        ]
        
        # Reduced parameter patterns focusing on effective variations
        self.param_patterns = [
            "",
            "*",
            "../",
            "%2e%2e%2f",
        ]
        
        # Cache-related headers for reference
        self.cache_headers = [
            "X-Cache",
            "X-Cache-Hit",
            "CF-Cache-Status",
            "Age",
            "Cache-Control",
        ]
        
        # Initialize variation cache
        self._variation_cache = lru_cache(maxsize=1000)(self._generate_variations_uncached)

    def generate_variations(self, url: str) -> List[str]:
        """
        Generate optimized URL permutations for testing.
        
        Args:
            url (str): Base URL to generate variations from
            
        Returns:
            List[str]: List of unique, relevant URL variations
        """
        try:
            # Normalize URL first
            normalized_url = self.normalize_url(url)
            
            # Use cached generation if available
            variations = self._variation_cache(normalized_url)
            
            # Log generation statistics
            logger.debug(f"Generated {len(variations)} variations for {url}")
            return variations
            
        except Exception as e:
            logger.error(f"Error generating URL variations: {str(e)}")
            return [url]

    def _generate_variations_uncached(self, url: str) -> List[str]:
        """
        Internal method to generate variations without caching.
        
        Args:
            url (str): Normalized URL to generate variations from
            
        Returns:
            List[str]: List of variations
        """
        variations: Set[str] = {url}
        parsed = urlparse(url)
        
        # Extract components
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        params = parse_qs(parsed.query)
        
        # Generate path variations efficiently
        path_variations = self._generate_path_variations(path)
        
        # Add path variations within limits
        for path_var in itertools.islice(path_variations, self.max_variations // 2):
            if parsed.query:
                variations.add(f"{base}{path_var}?{parsed.query}")
            else:
                variations.add(f"{base}{path_var}")
            
            if len(variations) >= self.max_variations:
                break
        
        # Generate parameter variations if space allows
        if params and len(variations) < self.max_variations:
            param_variations = self._generate_param_variations(params)
            remaining_slots = self.max_variations - len(variations)
            
            for param_var in itertools.islice(param_variations, remaining_slots):
                variations.add(f"{base}{path}?{param_var}")
        
        # Convert to list and apply final limit
        return list(variations)[:self.max_variations]

    def _generate_path_variations(self, path: str) -> Generator[str, None, None]:
        """
        Generate optimized path variations using a generator.
        
        Args:
            path (str): Original URL path
            
        Yields:
            str: Path variation
        """
        # Split path into components
        path_parts = [p for p in path.split('/') if p]
        
        # Base path variations
        yield path
        yield path.rstrip('/') + '/'
        
        # Generate variations for each path segment
        for i in range(len(path_parts) + 1):
            current_parts = path_parts[:i]
            base_path = '/' + '/'.join(current_parts)
            
            # Yield basic variations
            yield base_path
            
            # Add selected pattern variations
            for pattern in self.path_patterns:
                yield base_path + pattern
            
            # Add selective encoding variations
            if i > 0:
                yield base_path.replace('/', '%2f')

    def _generate_param_variations(self, params: Dict) -> Generator[str, None, None]:
        """
        Generate optimized parameter variations using a generator.
        
        Args:
            params (Dict): Original URL parameters
            
        Yields:
            str: Parameter variation
        """
        # Original parameters
        yield urlencode(params, doseq=True)
        
        # Generate variations for each parameter
        for param_name in params:
            orig_value = params[param_name][0]
            
            # Basic parameter variations
            for pattern in self.param_patterns:
                new_params = params.copy()
                new_params[param_name] = [orig_value + pattern]
                yield urlencode(new_params, doseq=True)
            
            # Add cache buster with timestamp
            new_params = params.copy()
            new_params['_'] = ['timestamp']
            yield urlencode(new_params, doseq=True)

    @staticmethod
    def normalize_url(url: str) -> str:
        """
        Normalize a URL by removing redundant components and standardizing format.
        
        Args:
            url (str): URL to normalize
            
        Returns:
            str: Normalized URL
        """
        try:
            # Parse URL
            parsed = urlparse(url)
            
            # Normalize scheme
            scheme = parsed.scheme.lower()
            
            # Normalize host
            host = parsed.netloc.lower()
            
            # Normalize path
            path = parsed.path
            while '//' in path:
                path = path.replace('//', '/')
            if not path:
                path = '/'
            
            # Normalize query parameters
            params = parse_qs(parsed.query)
            normalized_query = urlencode(sorted(params.items()), doseq=True) if params else ''
            
            # Reconstruct URL
            normalized = urlunparse((
                scheme,
                host,
                path,
                '',  # params
                normalized_query,
                ''   # fragment
            ))
            
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing URL: {str(e)}")
            return url

    def is_same_origin(self, url1: str, url2: str) -> bool:
        """
        Check if two URLs have the same origin.
        
        Args:
            url1 (str): First URL
            url2 (str): Second URL
            
        Returns:
            bool: True if URLs have the same origin
        """
        try:
            parsed1 = urlparse(url1)
            parsed2 = urlparse(url2)
            
            return (
                parsed1.scheme.lower() == parsed2.scheme.lower() and
                parsed1.netloc.lower() == parsed2.netloc.lower()
            )
            
        except Exception as e:
            logger.error(f"Error comparing URL origins: {str(e)}")
            return False

    def get_variation_info(self, url: str) -> Dict:
        """
        Get information about potential variations for a URL.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            Dict: Information about potential variations
        """
        try:
            parsed = urlparse(url)
            
            return {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path_segments': len([p for p in parsed.path.split('/') if p]),
                'query_params': len(parse_qs(parsed.query)),
                'potential_variations': min(
                    self.max_variations,
                    len(self.path_patterns) * (len([p for p in parsed.path.split('/') if p]) + 1) +
                    len(self.param_patterns) * len(parse_qs(parsed.query))
                ),
                'normalized_url': self.normalize_url(url)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing URL: {str(e)}")
            return {'error': str(e)}

if __name__ == "__main__":
    # Test URL manipulator functionality
    manipulator = URLManipulator(max_variations=50)
    test_url = "http://example.com/path/to/resource?param=value"
    
    # Generate and print variations
    variations = manipulator.generate_variations(test_url)
    print(f"Generated {len(variations)} variations for {test_url}")
    for var in variations:
        print(f"- {var}")
    
    # Print variation info
    info = manipulator.get_variation_info(test_url)
    print("\nVariation Info:")
    for key, value in info.items():
        print(f"{key}: {value}")
