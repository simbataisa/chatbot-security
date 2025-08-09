# ChatGuard - Chatbot Security Testing Tool

ChatGuard is a comprehensive Python-based command-line tool designed to perform automated security testing on chatbots. It identifies common vulnerabilities by sending various malicious payloads and analyzing responses for signs of weakness.

## Features

- **SQL Injection Testing**: Detects SQL injection vulnerabilities using time-based, boolean-based, and error-based techniques
- **Cross-Site Scripting (XSS) Testing**: Identifies XSS vulnerabilities through payload reflection analysis
- **Command Injection Testing**: Tests for command injection vulnerabilities with system command payloads
- **Fuzzing**: Generates random and malformed inputs to test application robustness
- **Sensitive Data Exposure**: Probes for information disclosure vulnerabilities
- **Comprehensive Reporting**: Generates detailed reports in both console and Markdown formats
- **Configurable**: Fully configurable via YAML configuration files
- **Modular Architecture**: Easy to extend with additional security tests

## Installation

1. **Clone or download the ChatGuard tool**
2. **Install required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Before running ChatGuard, you need to configure it for your target chatbot:

1. **Copy the example configuration:**
   ```bash
   cp config.yaml my-chatbot-config.yaml
   ```

2. **Edit the configuration file** to match your chatbot's API:
   ```yaml
   # Target chatbot API endpoint
   api_endpoint: "https://your-chatbot-api.com/chat"
   
   # HTTP method
   http_method: "POST"
   
   # Headers (including authentication)
   headers:
     Content-Type: "application/json"
     Authorization: "Bearer your-api-token"
   
   # Request body template with payload placeholder
   request_body_template:
     message: "%%PAYLOAD%%"
     user_id: "test_user"
   ```

### Configuration Options

- **api_endpoint**: The URL of your chatbot's API endpoint
- **http_method**: HTTP method to use (GET, POST, PUT, PATCH, DELETE)
- **headers**: HTTP headers including authentication tokens
- **request_body_template**: JSON template with `%%PAYLOAD%%` placeholder
- **timeout**: Request timeout in seconds (optional, default: 10)
- **request_delay**: Delay between requests in seconds (optional, default: 0.1)

## Usage

### Run All Security Tests
```bash
python main.py --config my-chatbot-config.yaml
```

### Run Specific Tests
```bash
# SQL Injection only
python main.py --config my-chatbot-config.yaml --test sqli

# XSS only
python main.py --config my-chatbot-config.yaml --test xss

# Command Injection only
python main.py --config my-chatbot-config.yaml --test command_injection

# Fuzzing only
python main.py --config my-chatbot-config.yaml --test fuzzing

# Sensitive Data Exposure only
python main.py --config my-chatbot-config.yaml --test sensitive_data
```

### Command Line Options

- `--config`: Path to configuration YAML file (required)
- `--test`: Run only a specific test module (optional)
- `--help`: Show help message and available options

## Security Test Modules

### 1. SQL Injection (sqli)
Tests for SQL injection vulnerabilities using:
- Boolean-based blind injection
- Time-based blind injection
- Error-based injection
- UNION-based injection
- Stacked queries

### 2. Cross-Site Scripting (xss)
Detects XSS vulnerabilities by:
- Testing payload reflection in responses
- Analyzing JavaScript execution contexts
- Checking HTML attribute contexts
- Testing various encoding bypasses

### 3. Command Injection (command_injection)
Identifies command injection through:
- System command execution detection
- Time-based command injection
- Error message analysis
- Command output pattern matching

### 4. Fuzzing (fuzzing)
Tests application robustness with:
- Very long input strings
- Special characters and encoding
- Format string attacks
- Buffer overflow attempts
- Unicode and control characters
- Random malformed data

### 5. Sensitive Data Exposure (sensitive_data)
Probes for information disclosure:
- API keys and tokens
- Database credentials
- Personal information (PII)
- System configuration data
- File contents and paths

## Output and Reporting

ChatGuard generates comprehensive reports in multiple formats:

### Console Output
- Real-time vulnerability detection
- Color-coded severity levels
- Progress indicators
- Summary statistics

### Markdown Report (report.md)
- Executive summary
- Detailed findings with evidence
- Risk level definitions
- Remediation recommendations
- Professional formatting

### Report Sections
- **Executive Summary**: High-level overview and statistics
- **Detailed Findings**: Complete vulnerability details with payloads and responses
- **Risk Levels**: High, Medium, and Low risk categorization
- **Recommendations**: Specific remediation guidance

## Payload Files

ChatGuard uses external payload files for flexibility:

- `payloads/sqli.txt`: SQL injection payloads
- `payloads/xss.txt`: Cross-site scripting payloads
- `payloads/command_injection.txt`: Command injection payloads
- `payloads/sensitive_data.txt`: Information disclosure payloads

You can customize these files to add your own test cases.

## Security Considerations

### Responsible Testing
- Only test chatbots you own or have explicit permission to test
- Use ChatGuard in controlled environments
- Be aware that some tests may cause service disruption
- Follow responsible disclosure practices for any vulnerabilities found

### Rate Limiting
- ChatGuard includes built-in delays between requests
- Adjust `request_delay` in configuration if needed
- Monitor target system performance during testing

## Extending ChatGuard

### Adding New Test Modules

1. Create a new tester class inheriting from `BaseTester`
2. Implement required methods: `load_payloads()` and `analyze_response()`
3. Add the tester to the main ChatGuard class
4. Create corresponding payload files

### Custom Payloads

Add custom payloads to existing payload files or create new ones:
```python
# In your custom tester
def load_payloads(self):
    # Load from custom file or return custom list
    return ['custom_payload_1', 'custom_payload_2']
```

## Troubleshooting

### Common Issues

1. **Configuration Validation Failed**
   - Check YAML syntax
   - Ensure all required fields are present
   - Verify API endpoint URL format

2. **Connection Errors**
   - Verify API endpoint is accessible
   - Check authentication credentials
   - Confirm network connectivity

3. **No Vulnerabilities Found**
   - Verify payload placeholder (%%PAYLOAD%%) in request template
   - Check if chatbot is properly processing inputs
   - Review response analysis logic

### Debug Mode

For troubleshooting, you can modify the code to add debug output:
```python
# Add to any tester's analyze_response method
print(f"DEBUG: Payload: {payload}")
print(f"DEBUG: Response: {response}")
```

## Contributing

To contribute to ChatGuard:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems.

## Disclaimer

ChatGuard is designed for authorized security testing only. The developers are not responsible for any misuse of this tool. Always ensure you have explicit permission before testing any chatbot or system you do not own.