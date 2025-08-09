"""
Configuration validator module.
"""

from colorama import Fore

class ConfigValidator:
    """Validates ChatGuard configuration files."""
    
    def __init__(self):
        """Initialize the validator."""
        self.required_fields = [
            'api_endpoint',
            'http_method',
            'headers',
            'request_body_template'
        ]
        self.valid_http_methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
    
    def validate(self, config):
        """Validate the configuration dictionary."""
        if not isinstance(config, dict):
            print(f"{Fore.RED}Configuration must be a dictionary")
            return False
        
        # Check required fields
        for field in self.required_fields:
            if field not in config:
                print(f"{Fore.RED}Missing required field: {field}")
                return False
        
        # Validate API endpoint
        if not self._validate_api_endpoint(config['api_endpoint']):
            return False
        
        # Validate HTTP method
        if not self._validate_http_method(config['http_method']):
            return False
        
        # Validate headers
        if not self._validate_headers(config['headers']):
            return False
        
        # Validate request body template
        if not self._validate_request_body_template(config['request_body_template']):
            return False
        
        # Validate optional fields
        if 'timeout' in config and not self._validate_timeout(config['timeout']):
            return False
        
        print(f"{Fore.GREEN}Configuration validation passed")
        return True
    
    def _validate_api_endpoint(self, endpoint):
        """Validate the API endpoint URL."""
        if not isinstance(endpoint, str):
            print(f"{Fore.RED}api_endpoint must be a string")
            return False
        
        if not endpoint.startswith(('http://', 'https://')):
            print(f"{Fore.RED}api_endpoint must start with http:// or https://")
            return False
        
        if len(endpoint) < 10:  # Minimum reasonable URL length
            print(f"{Fore.RED}api_endpoint appears to be too short")
            return False
        
        return True
    
    def _validate_http_method(self, method):
        """Validate the HTTP method."""
        if not isinstance(method, str):
            print(f"{Fore.RED}http_method must be a string")
            return False
        
        if method.upper() not in self.valid_http_methods:
            print(f"{Fore.RED}http_method must be one of: {', '.join(self.valid_http_methods)}")
            return False
        
        return True
    
    def _validate_headers(self, headers):
        """Validate the headers dictionary."""
        if not isinstance(headers, dict):
            print(f"{Fore.RED}headers must be a dictionary")
            return False
        
        # Check that all header names and values are strings
        for key, value in headers.items():
            if not isinstance(key, str):
                print(f"{Fore.RED}Header name must be a string: {key}")
                return False
            
            if not isinstance(value, str):
                print(f"{Fore.RED}Header value must be a string: {value}")
                return False
        
        return True
    
    def _validate_request_body_template(self, template):
        """Validate the request body template."""
        if not isinstance(template, dict):
            print(f"{Fore.RED}request_body_template must be a dictionary")
            return False
        
        # Check if the template contains the payload placeholder
        template_str = str(template)
        if '%%PAYLOAD%%' not in template_str:
            print(f"{Fore.YELLOW}Warning: request_body_template does not contain %%PAYLOAD%% placeholder")
            print(f"{Fore.YELLOW}This means payloads will not be injected into requests")
        
        return True
    
    def _validate_timeout(self, timeout):
        """Validate the timeout value."""
        if not isinstance(timeout, (int, float)):
            print(f"{Fore.RED}timeout must be a number")
            return False
        
        if timeout <= 0:
            print(f"{Fore.RED}timeout must be greater than 0")
            return False
        
        if timeout > 300:  # 5 minutes seems like a reasonable maximum
            print(f"{Fore.YELLOW}Warning: timeout is very high ({timeout}s)")
        
        return True