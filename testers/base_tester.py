"""
Base tester class that all security testers inherit from.
"""

import requests
import time
import json
from abc import ABC, abstractmethod
from colorama import Fore, Style

class BaseTester(ABC):
    """Abstract base class for all security testers."""
    
    def __init__(self, config):
        """Initialize base tester with configuration."""
        self.config = config
        self.api_endpoint = config['api_endpoint']
        self.http_method = config.get('http_method', 'POST').upper()
        self.headers = config.get('headers', {})
        self.request_body_template = config.get('request_body_template', {})
        self.timeout = config.get('timeout', 10)
        self.results = []
    
    def send_request(self, payload):
        """Send a request with the given payload to the target chatbot."""
        try:
            # Replace placeholder in request body template
            # First, create a copy of the template
            request_body = self.request_body_template.copy()
            
            # Recursively replace %%PAYLOAD%% in the template
            def replace_payload(obj):
                if isinstance(obj, dict):
                    return {k: replace_payload(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [replace_payload(item) for item in obj]
                elif isinstance(obj, str):
                    return obj.replace('%%PAYLOAD%%', payload)
                else:
                    return obj
            
            request_body = replace_payload(request_body)
            
            start_time = time.time()
            
            if self.http_method == 'POST':
                response = requests.post(
                    self.api_endpoint,
                    json=request_body,
                    headers=self.headers,
                    timeout=self.timeout
                )
            elif self.http_method == 'GET':
                response = requests.get(
                    self.api_endpoint,
                    params=request_body,
                    headers=self.headers,
                    timeout=self.timeout
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {self.http_method}")
            
            response_time = time.time() - start_time
            
            return {
                'status_code': response.status_code,
                'response_time': response_time,
                'response_body': response.text,
                'headers': dict(response.headers)
            }
            
        except requests.exceptions.Timeout:
            return {
                'status_code': None,
                'response_time': self.timeout,
                'response_body': 'Request timed out',
                'headers': {},
                'error': 'timeout'
            }
        except requests.exceptions.RequestException as e:
            return {
                'status_code': None,
                'response_time': 0,
                'response_body': f'Request failed: {str(e)}',
                'headers': {},
                'error': str(e)
            }
    
    def add_finding(self, vulnerability_type, payload, response, reason, severity='Medium'):
        """Add a security finding to the results."""
        finding = {
            'vulnerability_type': vulnerability_type,
            'payload': payload,
            'response': response,
            'reason': reason,
            'severity': severity,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.results.append(finding)
        
        # Print finding to console
        color = Fore.RED if severity == 'High' else Fore.YELLOW if severity == 'Medium' else Fore.BLUE
        print(f"{color}[{severity}] {vulnerability_type} detected!")
        print(f"{Fore.WHITE}Payload: {payload}")
        print(f"{Fore.WHITE}Reason: {reason}")
        print("-" * 40)
    
    @abstractmethod
    def load_payloads(self):
        """Load test payloads. Must be implemented by subclasses."""
        pass
    
    @abstractmethod
    def analyze_response(self, payload, response):
        """Analyze response for vulnerabilities. Must be implemented by subclasses."""
        pass
    
    def run(self):
        """Run the security test."""
        payloads = self.load_payloads()
        print(f"{Fore.CYAN}Testing with {len(payloads)} payloads...")
        
        for i, payload in enumerate(payloads, 1):
            print(f"{Fore.WHITE}[{i}/{len(payloads)}] Testing payload...", end='\r')
            
            response = self.send_request(payload)
            self.analyze_response(payload, response)
            
            # Small delay to avoid overwhelming the target
            time.sleep(0.1)
        
        print(f"{Fore.GREEN}Completed {len(payloads)} tests. Found {len(self.results)} potential issues.")
        return self.results