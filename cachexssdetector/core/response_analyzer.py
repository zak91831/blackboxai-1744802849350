"""
Enhanced Response Analyzer for CacheXSSDetector.
Optimized analysis of server responses for XSS vulnerabilities with improved performance.
"""

from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass
import re
from bs4 import BeautifulSoup, SoupStrainer
from urllib.parse import urlparse, urljoin
import json
from functools import lru_cache
import hashlib
from ..utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class ResponseAnalysis:
    """Enhanced data class for storing response analysis results."""
    is_vulnerable: bool
    vulnerability_type: Optional[str]
    evidence: Optional[str]
    confidence: float
    context: Optional[str]
    location: Optional[str]
    severity: str
    description: str
    recommendation: str
    response_time: Optional[float] = None
    cache_status: Optional[Dict[str, Any]] = None
    reflection_count: int = 0
    payload_encoded: bool = False

class ResponseAnalyzer:
    """
    Optimized response analyzer with enhanced detection capabilities.
    """

    def __init__(self, cache_size: int = 1000):
        """
        Initialize Response Analyzer with optimized detection patterns.
        
        Args:
            cache_size (int): Size of LRU cache for analysis results
        """
        # Optimized XSS patterns with compiled regex
        self.xss_patterns = [
            (re.compile(r'<script[^>]*>.*?</script>', re.I | re.S), 'script tag'),
            (re.compile(r'javascript:', re.I), 'javascript protocol'),
            (re.compile(r'on\w+\s*=', re.I), 'event handler'),
            (re.compile(r'data:', re.I), 'data protocol'),
            (re.compile(r'<img[^>]*onerror=', re.I), 'img onerror'),
            (re.compile(r'<\w+[^>]*onclick=', re.I), 'onclick handler'),
            (re.compile(r'eval\s*\(', re.I), 'eval function'),
            (re.compile(r'document\.write', re.I), 'document.write'),
            (re.compile(r'innerHTML\s*=', re.I), 'innerHTML assignment')
        ]

        # Cache header patterns with compiled regex
        self.cache_headers = {
            'X-Cache': re.compile(r'hit|miss', re.I),
            'X-Cache-Hit': re.compile(r'1|0'),
            'CF-Cache-Status': re.compile(r'HIT|MISS|EXPIRED', re.I),
            'Age': re.compile(r'\d+'),
            'Cache-Control': re.compile(r'.*'),
            'ETag': re.compile(r'.*'),
            'Last-Modified': re.compile(r'.*'),
            'Expires': re.compile(r'.*')
        }

        # Content type patterns with compiled regex
        self.content_type_patterns = {
            'html': re.compile(r'text/html', re.I),
            'javascript': re.compile(r'(text|application)/javascript', re.I),
            'json': re.compile(r'application/json', re.I),
            'xml': re.compile(r'(text|application)/xml', re.I)
        }

        # Initialize analysis cache
        self._analysis_cache = lru_cache(maxsize=cache_size)(self._analyze_uncached)
        
        # Initialize sets for known safe and vulnerable patterns
        self.known_safe_patterns: Set[str] = set()
        self.known_vulnerable_patterns: Set[str] = set()

    async def analyze_response(
        self,
        response,
        payload: Optional[str] = None,
        context: Optional[str] = None
    ) -> ResponseAnalysis:
        """
        Analyze a response for vulnerabilities with optimized processing.
        
        Args:
            response: HTTP response object
            payload (Optional[str]): The payload that was used
            context (Optional[str]): Context of the test
            
        Returns:
            ResponseAnalysis: Analysis results
        """
        try:
            # Generate cache key for response
            cache_key = self._generate_cache_key(response, payload)
            
            # Check cache first
            if cached_result := self._analysis_cache(cache_key):
                logger.debug("Using cached analysis result")
                return cached_result

            # Extract response components
            headers = dict(response.headers)
            content = await response.text()
            status_code = response.status

            # Quick checks for known patterns
            if payload and self._is_known_pattern(payload):
                return self._get_known_result(payload)

            # Parallel analysis of different aspects
            is_cached = self._analyze_cache_headers(headers)
            content_type = self._determine_content_type(headers)
            
            # Optimize reflection search based on content type
            if content_type == 'html':
                reflection_points = self._find_reflection_points_html(content, payload)
            else:
                reflection_points = self._find_reflection_points_raw(content, payload)
            
            dom_sinks = self._analyze_dom_sinks(content) if content_type == 'html' else []
            
            # Vulnerability detection
            is_vulnerable, evidence = self._detect_vulnerability(
                content,
                payload,
                reflection_points,
                dom_sinks
            )

            # Calculate metrics
            confidence = self._calculate_confidence(
                is_vulnerable,
                reflection_points,
                dom_sinks,
                is_cached
            )

            severity = self._determine_severity(
                is_vulnerable,
                confidence,
                content_type,
                is_cached
            )

            # Create analysis result
            result = ResponseAnalysis(
                is_vulnerable=is_vulnerable,
                vulnerability_type="Cache-Based XSS" if is_cached else "Reflected XSS",
                evidence=evidence,
                confidence=confidence,
                context=context or content_type,
                location=self._determine_location(reflection_points),
                severity=severity,
                description=self._generate_description(is_vulnerable, is_cached, reflection_points),
                recommendation=self._generate_recommendation(is_vulnerable, is_cached),
                reflection_count=len(reflection_points),
                payload_encoded=payload and payload in content
            )

            # Update known patterns
            if payload:
                self._update_known_patterns(payload, is_vulnerable)

            return result

        except Exception as e:
            logger.error(f"Error analyzing response: {str(e)}")
            return ResponseAnalysis(
                is_vulnerable=False,
                vulnerability_type=None,
                evidence=None,
                confidence=0.0,
                context=None,
                location=None,
                severity="Info",
                description="Analysis failed due to error",
                recommendation="Retry the analysis",
                response_time=None,
                cache_status=None,
                reflection_count=0,
                payload_encoded=False
            )

    def _generate_cache_key(self, response, payload: Optional[str]) -> str:
        """Generate unique cache key for response analysis."""
        components = [
            str(response.status),
            str(sorted(response.headers.items())),
            payload or ''
        ]
        return hashlib.md5('|'.join(components).encode()).hexdigest()

    @staticmethod
    def _analyze_uncached(cache_key: str) -> Optional[ResponseAnalysis]:
        """Placeholder for LRU cache decorator."""
        return None

    def _is_known_pattern(self, payload: str) -> bool:
        """Check if payload matches known safe or vulnerable patterns."""
        return payload in self.known_safe_patterns or payload in self.known_vulnerable_patterns

    def _get_known_result(self, payload: str) -> ResponseAnalysis:
        """Get pre-computed result for known pattern."""
        is_vulnerable = payload in self.known_vulnerable_patterns
        return ResponseAnalysis(
            is_vulnerable=is_vulnerable,
            vulnerability_type="Known Pattern",
            evidence=payload if is_vulnerable else None,
            confidence=1.0,
            context="Known Pattern",
            location=None,
            severity="High" if is_vulnerable else "Info",
            description=f"Known {'vulnerable' if is_vulnerable else 'safe'} pattern",
            recommendation="Review security controls" if is_vulnerable else "No action needed"
        )

    def _update_known_patterns(self, payload: str, is_vulnerable: bool):
        """Update known pattern sets."""
        if is_vulnerable:
            self.known_vulnerable_patterns.add(payload)
        else:
            self.known_safe_patterns.add(payload)

    def _find_reflection_points_html(
        self,
        content: str,
        payload: Optional[str]
    ) -> List[Tuple[str, int, str]]:
        """
        Optimized reflection point detection for HTML content.
        """
        reflection_points = []
        
        if not payload:
            return reflection_points
            
        try:
            # Use SoupStrainer to parse only relevant tags
            parse_only = SoupStrainer(['script', 'img', 'a', 'input'])
            soup = BeautifulSoup(content, 'html.parser', parse_only=parse_only)
            
            # Search in different contexts efficiently
            for tag in soup:
                # Check tag attributes
                for attr, value in tag.attrs.items():
                    if payload in str(value):
                        pos = str(value).find(payload)
                        reflection_points.append(
                            ('attribute', pos, f"{tag.name}[{attr}]={value}")
                        )
                
                # Check tag content
                if tag.string and payload in tag.string:
                    pos = tag.string.find(payload)
                    reflection_points.append(
                        ('text', pos, str(tag))
                    )
            
            return reflection_points
            
        except Exception as e:
            logger.error(f"Error finding HTML reflection points: {str(e)}")
            return []

    def _find_reflection_points_raw(
        self,
        content: str,
        payload: Optional[str]
    ) -> List[Tuple[str, int, str]]:
        """
        Optimized reflection point detection for non-HTML content.
        """
        reflection_points = []
        
        if not payload:
            return reflection_points
            
        try:
            # Find all occurrences
            for match in re.finditer(re.escape(payload), content):
                pos = match.start()
                # Get surrounding context
                start = max(0, pos - 20)
                end = min(len(content), pos + len(payload) + 20)
                reflection_points.append(
                    ('raw', pos, content[start:end])
                )
            
            return reflection_points
            
        except Exception as e:
            logger.error(f"Error finding raw reflection points: {str(e)}")
            return []

    def _analyze_dom_sinks(self, content: str) -> List[Tuple[str, str]]:
        """
        Optimized DOM sink analysis with caching.
        """
        try:
            # Use SoupStrainer to parse only script tags
            parse_only = SoupStrainer('script')
            soup = BeautifulSoup(content, 'html.parser', parse_only=parse_only)
            
            sinks = []
            sink_patterns = [
                (re.compile(r'document\.write\s*\('), 'document.write'),
                (re.compile(r'\.innerHTML\s*='), 'innerHTML'),
                (re.compile(r'\.outerHTML\s*='), 'outerHTML'),
                (re.compile(r'eval\s*\('), 'eval'),
                (re.compile(r'setTimeout\s*\('), 'setTimeout'),
                (re.compile(r'setInterval\s*\('), 'setInterval')
            ]
            
            for script in soup:
                script_content = script.string or ''
                for pattern, sink_name in sink_patterns:
                    if pattern.search(script_content):
                        sinks.append((sink_name, 'script'))
            
            return sinks
            
        except Exception as e:
            logger.error(f"Error analyzing DOM sinks: {str(e)}")
            return []

    def _determine_content_type(self, headers: Dict[str, str]) -> str:
        """Determine content type from headers."""
        content_type = headers.get('Content-Type', '').lower()
        
        if 'text/html' in content_type:
            return 'html'
        elif 'application/json' in content_type:
            return 'json'
        elif 'text/javascript' in content_type or 'application/javascript' in content_type:
            return 'javascript'
        elif 'text/xml' in content_type or 'application/xml' in content_type:
            return 'xml'
        else:
            return 'raw'

    def _analyze_cache_headers(self, headers: Dict[str, str]) -> bool:
        """Optimized cache header analysis."""
        try:
            # Quick checks first
            if 'X-Cache' in headers and 'HIT' in headers['X-Cache'].upper():
                return True
                
            if 'CF-Cache-Status' in headers and 'HIT' in headers['CF-Cache-Status'].upper():
                return True
                
            # Check Cache-Control
            cache_control = headers.get('Cache-Control', '').lower()
            if 'no-store' in cache_control or 'no-cache' in cache_control:
                return False
                
            if 'public' in cache_control or 'max-age' in cache_control:
                return True
                
            # Check other indicators
            return bool(
                'Age' in headers or
                'ETag' in headers or
                'Last-Modified' in headers
            )
            
        except Exception as e:
            logger.error(f"Error analyzing cache headers: {str(e)}")
            return False

    def _detect_vulnerability(
        self,
        content: str,
        payload: Optional[str],
        reflection_points: List[Tuple[str, int, str]],
        dom_sinks: List[Tuple[str, str]]
    ) -> Tuple[bool, Optional[str]]:
        """Enhanced vulnerability detection."""
        try:
            if not payload:
                return False, None
                
            # Quick check for known patterns
            if payload in self.known_vulnerable_patterns:
                return True, f"Known vulnerable pattern: {payload}"
                
            if payload in self.known_safe_patterns:
                return False, None
                
            # Check reflection points
            for context, pos, surrounding in reflection_points:
                if context in ['script', 'attribute']:
                    return True, surrounding
                    
            # Check DOM sinks
            if dom_sinks and payload.lower() in content.lower():
                return True, f"DOM sink vulnerable to payload"
                
            # Check encoded variations
            encoded_variations = [
                payload.replace('<', '<').replace('>', '>'),
                payload.replace('"', '"'),
                payload.replace("'", '&#x27;')
            ]
            
            for encoded in encoded_variations:
                if encoded in content:
                    return True, f"Encoded payload found: {encoded}"
                    
            return False, None
            
        except Exception as e:
            logger.error(f"Error detecting vulnerability: {str(e)}")
            return False, None

    def _calculate_confidence(
        self,
        is_vulnerable: bool,
        reflection_points: List[Tuple[str, int, str]],
        dom_sinks: List[Tuple[str, str]],
        is_cached: bool
    ) -> float:
        """Enhanced confidence calculation."""
        if not is_vulnerable:
            return 0.0
            
        try:
            confidence = 0.5  # Base confidence
            
            # Reflection points analysis
            if reflection_points:
                confidence += 0.2
                dangerous_contexts = sum(
                    1 for context, _, _ in reflection_points
                    if context in ['script', 'attribute']
                )
                confidence += min(0.2, dangerous_contexts * 0.1)
                
            # DOM sinks analysis
            if dom_sinks:
                confidence += min(0.1, len(dom_sinks) * 0.02)
                
            # Cache status impact
            if is_cached:
                confidence += 0.1
                
            return min(1.0, confidence)
            
        except Exception as e:
            logger.error(f"Error calculating confidence: {str(e)}")
            return 0.5

    def _determine_severity(
        self,
        is_vulnerable: bool,
        confidence: float,
        content_type: str,
        is_cached: bool
    ) -> str:
        """Enhanced severity determination."""
        if not is_vulnerable:
            return "Info"
            
        try:
            # Base severity on confidence
            if confidence >= 0.8:
                severity = "High"
            elif confidence >= 0.5:
                severity = "Medium"
            else:
                severity = "Low"
                
            # Adjust based on content type
            if content_type == 'html' and confidence > 0.5:
                severity = "High"
                
            # Adjust based on caching
            if is_cached and severity in ["Medium", "High"]:
                severity = "Critical"
                
            return severity
            
        except Exception as e:
            logger.error(f"Error determining severity: {str(e)}")
            return "Info"

    def _determine_location(
        self,
        reflection_points: List[Tuple[str, int, str]]
    ) -> Optional[str]:
        """Enhanced location determination."""
        if not reflection_points:
            return None
            
        try:
            locations = []
            for context, pos, _ in reflection_points:
                locations.append(f"{context} at position {pos}")
            return "; ".join(locations)
            
        except Exception as e:
            logger.error(f"Error determining location: {str(e)}")
            return None

    def _generate_description(
        self,
        is_vulnerable: bool,
        is_cached: bool,
        reflection_points: List[Tuple[str, int, str]]
    ) -> str:
        """Enhanced description generation."""
        if not is_vulnerable:
            return "No vulnerability detected"
            
        try:
            description = []
            
            if is_cached:
                description.append("Cache-based XSS vulnerability detected")
            else:
                description.append("Reflected XSS vulnerability detected")
                
            if reflection_points:
                contexts = [context for context, _, _ in reflection_points]
                description.append(f"Payload reflected in {', '.join(set(contexts))} context(s)")
                
            return ". ".join(description)
            
        except Exception as e:
            logger.error(f"Error generating description: {str(e)}")
            return "Vulnerability analysis failed"

    def _generate_recommendation(
        self,
        is_vulnerable: bool,
        is_cached: bool
    ) -> str:
        """Enhanced recommendation generation."""
        if not is_vulnerable:
            return "No remediation needed"
            
        try:
            recommendations = [
                "Implement proper input validation and output encoding",
                "Use Content Security Policy (CSP) headers",
                "Sanitize user input before reflection in the response"
            ]
            
            if is_cached:
                recommendations.extend([
                    "Review caching policies",
                    "Implement cache key segmentation",
                    "Consider using private caching for sensitive content"
                ])
                
            return ". ".join(recommendations)
            
        except Exception as e:
            logger.error(f"Error generating recommendation: {str(e)}")
            return "Unable to generate recommendations"

if __name__ == "__main__":
    # Test response analyzer functionality
    analyzer = ResponseAnalyzer()
    
    # Mock response object for testing
    class MockResponse:
        def __init__(self):
            self.headers = {
                'Content-Type': 'text/html',
                'X-Cache': 'HIT'
            }
            self.text = '<script>alert("test")</script>'
            self.status_code = 200
    
    result = analyzer.analyze_response(MockResponse(), payload='alert("test")')
    print(f"Analysis Result: {result}")
