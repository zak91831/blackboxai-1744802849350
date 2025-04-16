"""
Header Manipulation Module for CacheXSSDetector.
Handles modification and testing of HTTP headers for vulnerability detection.
"""

from typing import Dict, List, Optional, Set
import random
import string
from datetime import datetime, timedelta
from email.utils import formatdate
import base64
from ..utils.logger import get_logger

logger = get_logger(__name__)

class HeaderManipulator:
    """
    Handles HTTP header manipulation for testing cache behavior and XSS vulnerabilities.
    """

    def __init__(self):
        """Initialize header manipulator with predefined test cases."""
        self.cache_headers = {
            'Cache-Control': [
                'no-cache',
                'no-store',
                'max-age=0',
                'max-age=3600',
                'public',
                'private',
                'must-revalidate',
                'proxy-revalidate',
                'immutable'
            ],
            'Pragma': [
                'no-cache'
            ],
            'If-None-Match': [
                '*',
                'W/"random-etag"',
                '"random-etag"'
            ],
            'If-Modified-Since': [
                'now',
                'now-1h',
                'now-1d'
            ]
        }

        self.custom_headers = {
            'X-Forwarded-For': [
                '127.0.0.1',
                '192.168.1.1',
                '10.0.0.1'
            ],
            'X-Forwarded-Host': [
                'example.com',
                'internal-server',
                'localhost'
            ],
            'X-Forwarded-Proto': [
                'http',
                'https'
            ]
        }

        self.security_headers = {
            'X-XSS-Protection': [
                '0',
                '1',
                '1; mode=block'
            ],
            'X-Content-Type-Options': [
                'nosniff'
            ],
            'X-Frame-Options': [
                'DENY',
                'SAMEORIGIN'
            ]
        }

    def generate_headers(
        self,
        base_headers: Optional[Dict[str, str]] = None,
        include_cache: bool = True,
        include_custom: bool = True,
        include_security: bool = True
    ) -> List[Dict[str, str]]:
        """
        Generate various header combinations for testing.
        
        Args:
            base_headers (Optional[Dict[str, str]]): Base headers to include
            include_cache (bool): Include cache-related headers
            include_custom (bool): Include custom headers
            include_security (bool): Include security headers
            
        Returns:
            List[Dict[str, str]]: List of header combinations
        """
        headers_list = []
        base = base_headers or {}

        try:
            # Generate different header combinations
            if include_cache:
                cache_variations = self._generate_cache_variations()
                headers_list.extend(self._merge_headers(base, var) for var in cache_variations)

            if include_custom:
                custom_variations = self._generate_custom_variations()
                headers_list.extend(self._merge_headers(base, var) for var in custom_variations)

            if include_security:
                security_variations = self._generate_security_variations()
                headers_list.extend(self._merge_headers(base, var) for var in security_variations)

            # Deduplicate headers
            unique_headers = []
            seen = set()
            for headers in headers_list:
                headers_tuple = tuple(sorted(headers.items()))
                if headers_tuple not in seen:
                    seen.add(headers_tuple)
                    unique_headers.append(headers)

            logger.info(f"Generated {len(unique_headers)} unique header combinations")
            return unique_headers

        except Exception as e:
            logger.error(f"Error generating headers: {str(e)}")
            return [base]

    def _generate_cache_variations(self) -> List[Dict[str, str]]:
        """
        Generate variations of cache-related headers.
        
        Returns:
            List[Dict[str, str]]: List of cache header variations
        """
        variations = []

        try:
            # Generate ETag values
            etags = [
                f'W/"{self._generate_random_string(8)}"',
                f'"{self._generate_random_string(12)}"'
            ]

            # Generate timestamps
            timestamps = [
                formatdate(timeval=None, localtime=False),  # Current time
                formatdate(timeval=(datetime.now() - timedelta(hours=1)).timestamp()),
                formatdate(timeval=(datetime.now() - timedelta(days=1)).timestamp())
            ]

            # Combine Cache-Control variations
            for cache_control in self.cache_headers['Cache-Control']:
                headers = {'Cache-Control': cache_control}
                
                # Add ETag variations
                for etag in etags:
                    etag_headers = headers.copy()
                    etag_headers['If-None-Match'] = etag
                    variations.append(etag_headers)

                # Add timestamp variations
                for timestamp in timestamps:
                    time_headers = headers.copy()
                    time_headers['If-Modified-Since'] = timestamp
                    variations.append(time_headers)

            return variations

        except Exception as e:
            logger.error(f"Error generating cache variations: {str(e)}")
            return []

    def _generate_custom_variations(self) -> List[Dict[str, str]]:
        """
        Generate variations of custom headers.
        
        Returns:
            List[Dict[str, str]]: List of custom header variations
        """
        variations = []

        try:
            # Generate combinations of custom headers
            for x_forwarded_for in self.custom_headers['X-Forwarded-For']:
                for x_forwarded_host in self.custom_headers['X-Forwarded-Host']:
                    for x_forwarded_proto in self.custom_headers['X-Forwarded-Proto']:
                        variations.append({
                            'X-Forwarded-For': x_forwarded_for,
                            'X-Forwarded-Host': x_forwarded_host,
                            'X-Forwarded-Proto': x_forwarded_proto
                        })

            # Add some random custom headers
            for _ in range(3):
                header_name = f'X-Custom-{self._generate_random_string(6)}'
                header_value = self._generate_random_string(10)
                variations.append({header_name: header_value})

            return variations

        except Exception as e:
            logger.error(f"Error generating custom variations: {str(e)}")
            return []

    def _generate_security_variations(self) -> List[Dict[str, str]]:
        """
        Generate variations of security headers.
        
        Returns:
            List[Dict[str, str]]: List of security header variations
        """
        variations = []

        try:
            # Generate combinations of security headers
            for xss_protection in self.security_headers['X-XSS-Protection']:
                for content_type_options in self.security_headers['X-Content-Type-Options']:
                    for frame_options in self.security_headers['X-Frame-Options']:
                        variations.append({
                            'X-XSS-Protection': xss_protection,
                            'X-Content-Type-Options': content_type_options,
                            'X-Frame-Options': frame_options
                        })

            return variations

        except Exception as e:
            logger.error(f"Error generating security variations: {str(e)}")
            return []

    def generate_test_cases(self, url: str) -> List[Dict[str, str]]:
        """
        Generate specific test cases for a URL.
        
        Args:
            url (str): Target URL
            
        Returns:
            List[Dict[str, str]]: List of test case headers
        """
        test_cases = []

        try:
            # Cache bypass test cases
            test_cases.extend([
                {'Cache-Control': 'no-cache, no-store, must-revalidate'},
                {'Pragma': 'no-cache'},
                {'Cache-Control': 'max-age=0'},
            ])

            # Cache poisoning test cases
            test_cases.extend([
                {'X-Forwarded-Host': 'evil.com'},
                {'X-Forwarded-Scheme': 'https'},
                {'X-Original-URL': '/admin'},
            ])

            # XSS test cases
            test_cases.extend([
                {'X-XSS-Protection': '0'},
                {'Content-Security-Policy': 'default-src *'},
                {'X-Content-Type-Options': 'nosniff'},
            ])

            return test_cases

        except Exception as e:
            logger.error(f"Error generating test cases: {str(e)}")
            return []

    def _merge_headers(
        self,
        base: Dict[str, str],
        additional: Dict[str, str]
    ) -> Dict[str, str]:
        """
        Merge two header dictionaries.
        
        Args:
            base (Dict[str, str]): Base headers
            additional (Dict[str, str]): Additional headers
            
        Returns:
            Dict[str, str]: Merged headers
        """
        merged = base.copy()
        merged.update(additional)
        return merged

    def _generate_random_string(self, length: int) -> str:
        """
        Generate a random string of specified length.
        
        Args:
            length (int): Length of string to generate
            
        Returns:
            str: Random string
        """
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def analyze_response_headers(
        self,
        headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Analyze response headers for security implications.
        
        Args:
            headers (Dict[str, str]): Response headers to analyze
            
        Returns:
            Dict[str, Any]: Analysis results
        """
        analysis = {
            'security_headers': {
                'present': [],
                'missing': []
            },
            'cache_headers': {
                'present': [],
                'configuration': {}
            },
            'recommendations': []
        }

        try:
            # Check security headers
            security_headers = [
                'X-XSS-Protection',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'Content-Security-Policy',
                'Strict-Transport-Security'
            ]

            for header in security_headers:
                if header in headers:
                    analysis['security_headers']['present'].append(header)
                else:
                    analysis['security_headers']['missing'].append(header)
                    analysis['recommendations'].append(f"Add {header} header")

            # Analyze cache headers
            cache_headers = ['Cache-Control', 'Pragma', 'Expires', 'ETag']
            for header in cache_headers:
                if header in headers:
                    analysis['cache_headers']['present'].append(header)
                    analysis['cache_headers']['configuration'][header] = headers[header]

            # Add recommendations based on analysis
            if 'Cache-Control' in headers:
                if 'private' not in headers['Cache-Control'].lower():
                    analysis['recommendations'].append(
                        "Consider adding 'private' directive to Cache-Control"
                    )

            return analysis

        except Exception as e:
            logger.error(f"Error analyzing response headers: {str(e)}")
            return {'error': str(e)}

if __name__ == "__main__":
    # Test header manipulator functionality
    manipulator = HeaderManipulator()
    
    # Generate test headers
    test_headers = manipulator.generate_headers(
        base_headers={'User-Agent': 'Test/1.0'},
        include_cache=True
    )
    
    print(f"Generated {len(test_headers)} header combinations")
    for headers in test_headers[:5]:  # Print first 5 combinations
        print(f"Headers: {headers}")
