#!/usr/bin/env python3
"""
ChatGuard Demo Script
Demonstrates the ChatGuard tool functionality with a mock setup.
"""

import sys
import time
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def print_banner():
    """Print ChatGuard banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ██████╗██╗  ██╗ █████╗ ████████╗ ██████╗ ██╗   ██╗ █████╗  ║
    ║  ██╔════╝██║  ██║██╔══██╗╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗ ║
    ║  ██║     ███████║███████║   ██║   ██║  ███╗██║   ██║███████║ ║
    ║  ██║     ██╔══██║██╔══██║   ██║   ██║   ██║██║   ██║██╔══██║ ║
    ║  ╚██████╗██║  ██║██║  ██║   ██║   ╚██████╔╝╚██████╔╝██║  ██║ ║
    ║   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ║
    ║                                                               ║
    ║           Automated Chatbot Security Testing Tool            ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(f"{Fore.CYAN}{banner}")

def demo_features():
    """Demonstrate ChatGuard features."""
    print(f"{Fore.GREEN}{Style.BRIGHT}🚀 ChatGuard Features:")
    print()
    
    features = [
        ("🔍 SQL Injection Testing", "Detects SQL injection vulnerabilities using multiple techniques"),
        ("🌐 Cross-Site Scripting (XSS)", "Identifies XSS vulnerabilities through payload analysis"),
        ("⚡ Command Injection", "Tests for command injection with system commands"),
        ("🎯 Fuzzing", "Generates random inputs to test application robustness"),
        ("🔐 Sensitive Data Exposure", "Probes for information disclosure vulnerabilities"),
        ("📊 Comprehensive Reporting", "Generates detailed reports in multiple formats"),
        ("⚙️  Configurable", "Fully configurable via YAML files"),
        ("🧩 Modular Architecture", "Easy to extend with additional security tests")
    ]
    
    for feature, description in features:
        print(f"{Fore.YELLOW}{feature}")
        print(f"{Fore.WHITE}   {description}")
        print()
        time.sleep(0.5)

def demo_usage():
    """Show usage examples."""
    print(f"{Fore.GREEN}{Style.BRIGHT}📖 Usage Examples:")
    print()
    
    examples = [
        ("Run all tests:", "python main.py --config config.yaml"),
        ("SQL injection only:", "python main.py --config config.yaml --test sqli"),
        ("XSS testing only:", "python main.py --config config.yaml --test xss"),
        ("Command injection:", "python main.py --config config.yaml --test command_injection"),
        ("Fuzzing tests:", "python main.py --config config.yaml --test fuzzing"),
        ("Sensitive data:", "python main.py --config config.yaml --test sensitive_data")
    ]
    
    for description, command in examples:
        print(f"{Fore.CYAN}{description}")
        print(f"{Fore.WHITE}   {command}")
        print()
        time.sleep(0.3)

def demo_config():
    """Show configuration example."""
    print(f"{Fore.GREEN}{Style.BRIGHT}⚙️  Configuration Example:")
    print()
    
    config_example = """
api_endpoint: "https://api.example.com/chat"
http_method: "POST"
headers:
  Content-Type: "application/json"
  Authorization: "Bearer your-token"
request_body_template:
  message: "%%PAYLOAD%%"
  user_id: "test_user"
timeout: 15
    """
    
    print(f"{Fore.YELLOW}{config_example}")

def demo_security_tests():
    """Demonstrate security test types."""
    print(f"{Fore.GREEN}{Style.BRIGHT}🛡️  Security Test Modules:")
    print()
    
    tests = [
        ("SQL Injection", [
            "Boolean-based blind injection",
            "Time-based blind injection", 
            "Error-based injection",
            "UNION-based injection"
        ]),
        ("Cross-Site Scripting", [
            "Reflected XSS detection",
            "JavaScript context analysis",
            "HTML attribute injection",
            "Filter bypass techniques"
        ]),
        ("Command Injection", [
            "System command execution",
            "Time-based detection",
            "Error message analysis",
            "Output pattern matching"
        ]),
        ("Fuzzing", [
            "Buffer overflow testing",
            "Special character injection",
            "Format string attacks",
            "Random data generation"
        ]),
        ("Sensitive Data", [
            "API key exposure",
            "Credential disclosure",
            "System information leakage",
            "Configuration data exposure"
        ])
    ]
    
    for test_name, techniques in tests:
        print(f"{Fore.CYAN}{Style.BRIGHT}{test_name}:")
        for technique in techniques:
            print(f"{Fore.WHITE}   • {technique}")
        print()
        time.sleep(0.4)

def main():
    """Main demo function."""
    print_banner()
    time.sleep(1)
    
    demo_features()
    time.sleep(1)
    
    demo_security_tests()
    time.sleep(1)
    
    demo_usage()
    time.sleep(1)
    
    demo_config()
    
    print(f"{Fore.GREEN}{Style.BRIGHT}🎯 Ready to start testing!")
    print(f"{Fore.WHITE}Configure your target in config.yaml and run:")
    print(f"{Fore.YELLOW}python main.py --config config.yaml")
    print()
    print(f"{Fore.BLUE}For more information, see README.md")

if __name__ == "__main__":
    main()