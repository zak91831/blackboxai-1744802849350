"""
Response Analyzer for CacheXSSDetector.
Analyzes server responses to detect XSS vulnerabilities and cache-related issues.
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import json
from ..utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class ResponseAnalysis:
    """Data class for storing response analysis results."""
    is_vulnerable: bool
    vulnerability_type: Optional[str]
    evidence: Optional[str]
    confidence: float
    context: Optional[str]
    location: Optional[str]
    severity: str
    description: str
    recommendation: str

class ResponseAnalyzer:
    """
    Analyzes HTTP responses for XSS vulnerabilities and cache-related issues.
    """

    def __init__(self):
        """Initialize Response Analyzer with detection patterns."""
        # XSS detection patterns
        self.xss_patterns = [
            (r'<script[^>]*>.*?</script>', 'script tag'),
            (r'javascript:', 'javascript protocol'),
            (r'on\w+\s*=', 'event handler'),
            (r'data:', 'data protocol'),
            (r'<img[^>]*onerror=', 'img onerror'),
            (r'<\w+[^>]*onclick=', 'onclick handler'),
            (r'eval\s*\(', 'eval function'),
            (r'document\.write', 'document.write'),
            (r'innerHTML\s*=', 'innerHTML assignment')
        ]

        # Cache header patterns
        self.cache_headers = {
            'X-Cache': r'hit|miss',
            'X-Cache-Hit': r'1|0',
            'CF-Cache-Status': r'HIT|MISS|EXPIRED',
            'Age': r'\d+',
            'Cache-Control': r'.*',
            'ETag': r'.*',
            'Last-Modified': r'.*',
            'Expires': r'.*'
        }

        # Content type patterns
        self.content_type_patterns = {
            'html': r'text/html',
            'javascript': r'(text|application)/javascript',
            'json': r'application/json',
            'xml': r'(text|application)/xml'
        }

    def analyze_response(
        self,
        response,
        payload: Optional[str] = None,
        context: Optional[str] = None
    ) -> ResponseAnalysis:
        """
        Analyze a response for vulnerabilities.
        
        Args:
            response: HTTP response object
            payload (Optional[str]): The payload that was used
            context (Optional[str]): Context of the test
            
        Returns:
            ResponseAnalysis: Analysis results
        """
        try:
            # Extract response components
            headers = dict(response.headers)
            content = response.text
            status_code = response.status_code

            # Analyze different aspects
            is_cached = self._analyze_cache_headers(headers)
            content_type = self._determine_content_type(headers)
            reflection_points = self._find_reflection_points(content, payload)
            dom_sinks = self._analyze_dom_sinks(content)
            
            # Determine if response is vulnerable
            is_vulnerable, evidence = self._detect_vulnerability(
                content,
                payload,
                reflection_points,
                dom_sinks
            )

            # Calculate confidence score
            confidence = self._calculate_confidence(
                is_vulnerable,
                reflection_points,
                dom_sinks,
                is_cached
            )

            # Determine severity
            severity = self._determine_severity(
                is_vulnerable,
                confidence,
                content_type,
                is_cached
            )

            return ResponseAnalysis(
                is_vulnerable=is_vulnerable,
                vulnerability_type="Cache-Based XSS" if is_cached else "Reflected XSS",
                evidence=evidence,
                confidence=confidence,
                context=context or content_type,
                location=self._determine_location(reflection_points),
                severity=severity,
                description=self._generate_description(is_vulnerable, is_cached, reflection_points),
                recommendation=self._generate_recommendation(is_vulnerable, is_cached)
            )

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
                recommendation="Retry the analysis"
            )

    def _analyze_cache_headers(self, headers: Dict[str, str]) -> bool:
        """
        Analyze cache-related headers.
        
        Args:
            headers (Dict[str, str]): Response headers
            
        Returns:
            bool: True if response appears to be cached
        """
        try:
            # Check explicit cache indicators
            if 'X-Cache' in headers and 'HIT' in headers['X-Cache'].upper():
                return True
                
            if 'CF-Cache-Status' in headers and 'HIT' in headers['CF-Cache-Status'].upper():
                return True
                
            # Check Cache-Control
            if 'Cache-Control' in headers:
                cache_control = headers['Cache-Control'].lower()
                if 'no-store' in cache_control or 'no-cache' in cache_control:
                    return False
                if 'public' in cache_control or 'max-age' in cache_control:
                    return True
                    
            # Check for other caching indicators
            return bool(
                'Age' in headers or
                'ETag' in headers or
                'Last-Modified' in headers
            )
            
        except Exception as e:
            logger.error(f"Error analyzing cache headers: {str(e)}")
            return False

    def _determine_content_type(self, headers: Dict[str, str]) -> str:
        """
        Determine the content type from headers.
        
        Args:
            headers (Dict[str, str]): Response headers
            
        Returns:
            str: Content type
        """
        content_type = headers.get('Content-Type', '').lower()
        
        for type_name, pattern in self.content_type_patterns.items():
            if re.search(pattern, content_type):
                return type_name
                
        return 'unknown'

    def _find_reflection_points(
        self,
        content: str,
        payload: Optional[str]
    ) -> List[Tuple[str, int, str]]:
        """
        Find points where payload is reflected in response.
        
        Args:
            content (str): Response content
            payload (Optional[str]): Payload to look for
            
        Returns:
            List[Tuple[str, int, str]]: List of (context, position, surrounding) tuples
        """
        reflection_points = []
        
        if not payload:
            return reflection_points
            
        try:
            # Parse HTML content
            soup = BeautifulSoup(content, 'html.parser')
            
            # Search in different contexts
            contexts = {
                'script': soup.find_all('script'),
                'attribute': soup.find_all(attrs=lambda x: any(payload in str(v) for v in x.values()) if x else False),
                'text': soup.find_all(text=re.compile(re.escape(payload)))
            }
            
            for context_type, elements in contexts.items():
                for element in elements:
                    pos = str(element).find(payload)
                    if pos >= 0:
                        # Get surrounding content for context
                        surrounding = str(element)[max(0, pos-20):min(len(str(element)), pos+len(payload)+20)]
                        reflection_points.append((context_type, pos, surrounding))
            
            return reflection_points
            
        except Exception as e:
            logger.error(f"Error finding reflection points: {str(e)}")
            return []

    def _analyze_dom_sinks(self, content: str) -> List[Tuple[str, str]]:
        """
        Analyze potential DOM-based XSS sinks.
        
        Args:
            content (str): Response content
            
        Returns:
            List[Tuple[str, str]]: List of (sink, context) tuples
        """
        sinks = []
        
        try:
            # Common DOM XSS sinks
            sink_patterns = [
                (r'document\.write\s*\(', 'document.write'),
                (r'\.innerHTML\s*=', 'innerHTML'),
                (r'\.outerHTML\s*=', 'outerHTML'),
                (r'eval\s*\(', 'eval'),
                (r'setTimeout\s*\(', 'setTimeout'),
                (r'setInterval\s*\(', 'setInterval')
            ]
            
            # Search for sinks in scripts
            soup = BeautifulSoup(content, 'html.parser')
            scripts = soup.find_all('script')
            
            for script in scripts:
                script_content = script.string or ''
                for pattern, sink_name in sink_patterns:
                    if re.search(pattern, script_content):
                        sinks.append((sink_name, 'script'))
            
            return sinks
            
        except Exception as e:
            logger.error(f"Error analyzing DOM sinks: {str(e)}")
            return []

    def _detect_vulnerability(
        self,
        content: str,
        payload: Optional[str],
        reflection_points: List[Tuple[str, int, str]],
        dom_sinks: List[Tuple[str, str]]
    ) -> Tuple[bool, Optional[str]]:
        """
        Detect if the response contains a vulnerability.
        
        Args:
            content (str): Response content
            payload (Optional[str]): Test payload
            reflection_points (List[Tuple[str, int, str]]): Reflection points
            dom_sinks (List[Tuple[str, str]]): DOM sinks
            
        Returns:
            Tuple[bool, Optional[str]]: (is_vulnerable, evidence)
        """
        try:
            if not payload:
                return False, None
                
            # Check for direct payload reflection in dangerous contexts
            for context, pos, surrounding in reflection_points:
                if context in ['script', 'attribute']:
                    return True, surrounding
                    
            # Check for DOM sinks with payload
            for sink, context in dom_sinks:
                if payload.lower() in content.lower():
                    return True, f"DOM sink: {sink} in {context}"
                    
            # Check for encoded versions of payload
            encoded_payload = payload.replace('<', '<').replace('>', '>')
            if encoded_payload in content:
                return True, f"Encoded payload found: {encoded_payload}"
                
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
        """
        Calculate confidence score for vulnerability detection.
        
        Args:
            is_vulnerable (bool): Whether vulnerability was detected
            reflection_points (List[Tuple[str, int, str]]): Reflection points
            dom_sinks (List[Tuple[str, str]]): DOM sinks
            is_cached (bool): Whether response is cached
            
        Returns:
            float: Confidence score (0-1)
        """
        try:
            if not is_vulnerable:
                return 0.0
                
            confidence = 0.5  # Base confidence
            
            # Adjust based on reflection points
            if reflection_points:
                confidence += 0.2
                # Additional confidence for dangerous contexts
                if any(context in ['script', 'attribute'] for context, _, _ in reflection_points):
                    confidence += 0.2
                    
            # Adjust based on DOM sinks
            if dom_sinks:
                confidence += 0.1
                
            # Adjust based on caching
            if is_cached:
                confidence += 0.1
                
            return min(confidence, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating confidence: {str(e)}")
            return 0.0

    def _determine_severity(
        self,
        is_vulnerable: bool,
        confidence: float,
        content_type: str,
        is_cached: bool
    ) -> str:
        """
        Determine the severity of a vulnerability.
        
        Args:
            is_vulnerable (bool): Whether vulnerability was detected
            confidence (float): Confidence score
            content_type (str): Content type
            is_cached (bool): Whether response is cached
            
        Returns:
            str: Severity level
        """
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
        """
        Determine the location of vulnerability in the response.
        
        Args:
            reflection_points (List[Tuple[str, int, str]]): Reflection points
            
        Returns:
            Optional[str]: Location description
        """
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
        """
        Generate a description of the vulnerability.
        
        Args:
            is_vulnerable (bool): Whether vulnerability was detected
            is_cached (bool): Whether response is cached
            reflection_points (List[Tuple[str, int, str]]): Reflection points
            
        Returns:
            str: Vulnerability description
        """
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

    def _generate_recommendation(self, is_vulnerable: bool, is_cached: bool) -> str:
        """
        Generate remediation recommendations.
        
        Args:
            is_vulnerable (bool): Whether vulnerability was detected
            is_cached (bool): Whether response is cached
            
        Returns:
            str: Recommendation
        """
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
