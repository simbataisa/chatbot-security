"""
Fuzzing tester module for generating random and malformed inputs.
"""

import random
import string
from .base_tester import BaseTester

class FuzzingTester(BaseTester):
    """Fuzzing vulnerability tester."""
    
    def __init__(self, config):
        """Initialize fuzzing tester."""
        super().__init__(config)
        self.vulnerability_type = "Fuzzing"
    
    def load_payloads(self):
        """Generate fuzzing payloads."""
        payloads = []
        
        # Very long strings
        payloads.extend(self._generate_long_strings())
        
        # Special characters and encoding
        payloads.extend(self._generate_special_characters())
        
        # Format string attacks
        payloads.extend(self._generate_format_strings())
        
        # Buffer overflow attempts
        payloads.extend(self._generate_buffer_overflow())
        
        # Unicode and encoding attacks
        payloads.extend(self._generate_unicode_attacks())
        
        # Null bytes and control characters
        payloads.extend(self._generate_control_characters())
        
        # Random data
        payloads.extend(self._generate_random_data())
        
        return payloads
    
    def _generate_long_strings(self):
        """Generate very long strings to test buffer handling."""
        payloads = []
        
        # Different lengths to test various buffer sizes
        lengths = [1000, 5000, 10000, 50000, 100000]
        
        for length in lengths:
            # Repeated characters
            payloads.append('A' * length)
            payloads.append('0' * length)
            payloads.append('x' * length)
            
            # Mixed content
            pattern = 'ABCD1234'
            payloads.append((pattern * (length // len(pattern) + 1))[:length])
        
        return payloads
    
    def _generate_special_characters(self):
        """Generate payloads with special characters."""
        special_chars = [
            '!@#$%^&*()_+-=[]{}|;:,.<>?',
            '`~',
            '\'"',
            '\\/',
            '\n\r\t',
            '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
        ]
        
        payloads = []
        
        for chars in special_chars:
            # Single character tests
            for char in chars:
                payloads.append(char)
                payloads.append(char * 100)
            
            # All characters together
            payloads.append(chars)
            payloads.append(chars * 10)
        
        return payloads
    
    def _generate_format_strings(self):
        """Generate format string attack payloads."""
        return [
            '%s%s%s%s%s%s%s%s%s%s',
            '%x%x%x%x%x%x%x%x%x%x',
            '%n%n%n%n%n%n%n%n%n%n',
            '%08x' * 10,
            '%d' * 20,
            '%s' * 20,
            '%p' * 10,
            '%#x' * 10,
            '%.1000d',
            '%.2000s',
            '%1000000d',
            '%s%p%x%d',
            '%2$s%3$p%1$d',
            '%1000$s',
            '%99999$n',
            '{0}' * 20,  # Python format strings
            '{foo}' * 10,
            '${var}' * 10,  # Shell variable expansion
        ]
    
    def _generate_buffer_overflow(self):
        """Generate buffer overflow test payloads."""
        payloads = []
        
        # Classic buffer overflow patterns
        patterns = ['A', 'B', 'C', '1', '0', 'X']
        sizes = [256, 512, 1024, 2048, 4096, 8192, 16384]
        
        for pattern in patterns:
            for size in sizes:
                payloads.append(pattern * size)
        
        # Cyclic patterns (useful for identifying exact overflow points)
        alphabet = string.ascii_lowercase
        for size in [100, 200, 500, 1000]:
            cyclic = ''
            for i in range(size):
                cyclic += alphabet[i % len(alphabet)]
            payloads.append(cyclic)
        
        return payloads
    
    def _generate_unicode_attacks(self):
        """Generate Unicode and encoding attack payloads."""
        return [
            # Unicode normalization attacks
            '\u0041\u0301',  # A with combining acute accent
            '\u00C1',        # Precomposed A with acute
            '\uFEFF',        # Byte order mark
            '\u202E',        # Right-to-left override
            '\u200B',        # Zero width space
            '\u2028',        # Line separator
            '\u2029',        # Paragraph separator
            
            # Overlong UTF-8 sequences (if not properly validated)
            '\xC0\xAF',      # Overlong encoding of '/'
            '\xE0\x80\xAF',  # Overlong encoding of '/'
            '\xF0\x80\x80\xAF',  # Overlong encoding of '/'
            
            # High Unicode code points
            '\U0001F4A9',    # Pile of poo emoji
            '\U0010FFFF',    # Highest valid Unicode code point
            
            # Mixed encodings
            'test\x80\x81\x82\x83',
            'test\xFF\xFE\xFD\xFC',
            
            # Double encoding
            '%2527',         # Double encoded single quote
            '%252F',         # Double encoded forward slash
        ]
    
    def _generate_control_characters(self):
        """Generate payloads with control characters."""
        payloads = []
        
        # ASCII control characters (0-31)
        for i in range(32):
            payloads.append(chr(i))
            payloads.append(chr(i) * 10)
            payloads.append(f'test{chr(i)}test')
        
        # DEL character (127)
        payloads.append(chr(127))
        payloads.append(chr(127) * 10)
        
        # Extended ASCII (128-255)
        for i in range(128, 256):
            try:
                payloads.append(chr(i))
            except ValueError:
                pass
        
        return payloads
    
    def _generate_random_data(self):
        """Generate random data payloads."""
        payloads = []
        
        # Random ASCII
        for length in [10, 50, 100, 500]:
            for _ in range(5):  # Generate 5 random strings of each length
                random_str = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))
                payloads.append(random_str)
        
        # Random bytes (as hex strings)
        for length in [10, 50, 100]:
            for _ in range(3):
                random_bytes = bytes([random.randint(0, 255) for _ in range(length)])
                try:
                    payloads.append(random_bytes.decode('utf-8', errors='ignore'))
                except:
                    pass
        
        return payloads
    
    def analyze_response(self, payload, response):
        """Analyze response for fuzzing-related vulnerabilities."""
        if response.get('error'):
            # Network errors might indicate server crash
            if 'connection' in response.get('error', '').lower():
                self.add_finding(
                    self.vulnerability_type,
                    payload,
                    response,
                    f"Connection error - possible server crash: {response.get('error')}",
                    'High'
                )
            return
        
        status_code = response.get('status_code')
        response_body = response.get('response_body', '')
        response_time = response.get('response_time', 0)
        
        # Check for server errors (5xx status codes)
        if status_code and 500 <= status_code < 600:
            self.add_finding(
                self.vulnerability_type,
                payload,
                response,
                f"Server error {status_code} - possible application crash or misconfiguration",
                'High'
            )
            return
        
        # Check for very slow responses (possible DoS)
        if response_time > 10:  # 10 seconds threshold
            self.add_finding(
                self.vulnerability_type,
                payload,
                response,
                f"Very slow response ({response_time:.2f}s) - possible DoS condition",
                'Medium'
            )
            return
        
        # Check for error messages that might leak information
        error_indicators = [
            'stack trace',
            'exception',
            'error',
            'warning',
            'debug',
            'traceback',
            'internal server error',
            'application error',
            'database error',
            'sql error',
            'file not found',
            'access denied',
            'permission denied',
            'out of memory',
            'buffer overflow',
            'segmentation fault',
            'null pointer',
            'assertion failed'
        ]
        
        response_lower = response_body.lower()
        for indicator in error_indicators:
            if indicator in response_lower:
                self.add_finding(
                    self.vulnerability_type,
                    payload,
                    response,
                    f"Error message detected: '{indicator}' - possible information disclosure",
                    'Low'
                )
                break
        
        # Check for very large responses (possible memory exhaustion)
        if len(response_body) > 1000000:  # 1MB threshold
            self.add_finding(
                self.vulnerability_type,
                payload,
                response,
                f"Very large response ({len(response_body)} bytes) - possible memory exhaustion",
                'Medium'
            )