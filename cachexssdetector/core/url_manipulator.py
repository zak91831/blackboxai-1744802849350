"""
URL Path Manipulation Module for CacheXSSDetector.
Handles generation and manipulation of URL paths for testing cache-based XSS vulnerabilities.
"""

from typing import List, Set
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import itertools
from ..utils.logger import get_logger

logger = get_logger(__name__)

class URLManipulator:
    """
    Handles URL manipulation and variation generation for testing.
    """
    
    def __init__(self):
        """Initialize URL Manipulator with common test patterns."""
        self.path_patterns = [
            "/",
            "/*",
            "/*/",
            "//",
            "/./",
            "/../",
            "/.../",
            "%2f",
            "%2F",
        ]
        
        self.param_patterns = [
            "",
            "*",
            "*/",
            "../",
            "..%2f",
            "%2e%2e%2f",
            "%252e%252e%252f",
        ]
        
        self.cache_headers = [
            "X-Cache",
            "X-Cache-Hit",
            "X-Cached",
            "CF-Cache-Status",
            "Age",
            "Cache-Control",
            "Expires",
        ]

    def generate_variations(self, url: str) -> List[str]:
        """
        Generate various URL permutations for testing.
        
        Args:
            url (str): Base URL to generate variations from
            
        Returns:
            List[str]: List of URL variations
        """
        try:
            parsed = urlparse(url)
            variations: Set[str] = {url}  # Use set to avoid duplicates
            
            # Extract base components
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path
            params = parse_qs(parsed.query)
            
            # Generate path variations
            path_parts = [p for p in path.split('/') if p]
            path_variations = self._generate_path_variations(path_parts)
            
            # Add path variations to results
            for path_var in path_variations:
                if parsed.query:
                    variations.add(f"{base}{path_var}?{parsed.query}")
                else:
                    variations.add(f"{base}{path_var}")
            
            # Generate parameter variations
            if params:
                param_variations = self._generate_param_variations(params)
                for param_var in param_variations:
                    variations.add(f"{base}{path}?{param_var}")
            
            # Add cache-buster variations
            variations.update(self._add_cache_busters(url))
            
            logger.debug(f"Generated {len(variations)} URL variations for {url}")
            return list(variations)
            
        except Exception as e:
            logger.error(f"Error generating URL variations: {str(e)}")
            return [url]

    def _generate_path_variations(self, path_parts: List[str]) -> Set[str]:
        """
        Generate variations of the URL path.
        
        Args:
            path_parts (List[str]): Parts of the URL path
            
        Returns:
            Set[str]: Set of path variations
        """
        variations: Set[str] = set()
        
        try:
            # Generate variations for each path segment
            for i in range(len(path_parts) + 1):
                current_parts = path_parts[:i]
                
                # Add basic path
                base_path = '/' + '/'.join(current_parts)
                variations.add(base_path)
                
                # Add path pattern variations
                for pattern in self.path_patterns:
                    var_path = base_path + pattern
                    variations.add(var_path)
                    
                    # Add encoded variations
                    variations.add(var_path.replace('/', '%2f'))
                    variations.add(var_path.replace('/', '%2F'))
                
                # Add double-encoding variations
                if i > 0:
                    double_encoded = base_path.replace('/', '%252f')
                    variations.add(double_encoded)
            
            return variations
            
        except Exception as e:
            logger.error(f"Error generating path variations: {str(e)}")
            return {'/'}

    def _generate_param_variations(self, params: dict) -> Set[str]:
        """
        Generate variations of URL parameters.
        
        Args:
            params (dict): Original URL parameters
            
        Returns:
            Set[str]: Set of parameter variations
        """
        variations: Set[str] = set()
        
        try:
            # Generate variations for each parameter
            for param_name in params:
                # Original parameter value
                orig_value = params[param_name][0]
                
                # Add basic parameter variations
                for pattern in self.param_patterns:
                    new_params = params.copy()
                    new_params[param_name] = [orig_value + pattern]
                    variations.add(urlencode(new_params, doseq=True))
                    
                    # Add encoded variations
                    encoded_value = orig_value.replace('/', '%2f')
                    new_params[param_name] = [encoded_value + pattern]
                    variations.add(urlencode(new_params, doseq=True))
                
                # Add cache-buster parameter
                new_params = params.copy()
                new_params['_'] = ['1234567890']
                variations.add(urlencode(new_params, doseq=True))
            
            return variations
            
        except Exception as e:
            logger.error(f"Error generating parameter variations: {str(e)}")
            return {urlencode(params, doseq=True)}

    def _add_cache_busters(self, url: str) -> Set[str]:
        """
        Add cache-busting parameters to URLs.
        
        Args:
            url (str): Original URL
            
        Returns:
            Set[str]: Set of URLs with cache-busting parameters
        """
        variations: Set[str] = set()
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Add timestamp cache buster
            params['_ts'] = ['1234567890']
            variations.add(f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}")
            
            # Add random cache buster
            params['_r'] = ['abc123']
            variations.add(f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}")
            
            # Add version cache buster
            params['_v'] = ['1.0']
            variations.add(f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}")
            
            return variations
            
        except Exception as e:
            logger.error(f"Error adding cache busters: {str(e)}")
            return {url}

    def normalize_url(self, url: str) -> str:
        """
        Normalize a URL by removing redundant slashes, resolving relative paths, etc.
        
        Args:
            url (str): URL to normalize
            
        Returns:
            str: Normalized URL
        """
        try:
            parsed = urlparse(url)
            
            # Normalize scheme
            scheme = parsed.scheme.lower()
            
            # Normalize host
            host = parsed.netloc.lower()
            
            # Normalize path
            path = parsed.path
            while '//' in path:
                path = path.replace('//', '/')
            
            # Normalize query parameters
            params = parse_qs(parsed.query)
            normalized_query = urlencode(sorted(params.items()), doseq=True) if params else ''
            
            # Reconstruct URL
            normalized = f"{scheme}://{host}{path}"
            if normalized_query:
                normalized += f"?{normalized_query}"
                
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

if __name__ == "__main__":
    # Test URL manipulator functionality
    manipulator = URLManipulator()
    test_url = "http://example.com/path/to/resource?param=value"
    variations = manipulator.generate_variations(test_url)
    print(f"Generated {len(variations)} variations for {test_url}")
    for var in variations:
        print(f"- {var}")
