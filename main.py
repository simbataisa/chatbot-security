#!/usr/bin/env python3
"""
ChatGuard - A Python-Based Chatbot Security Testing Tool
Main entry point for the security testing tool.
"""

import argparse
import sys
import yaml
from pathlib import Path
from colorama import init, Fore, Style
from testers.sqli_tester import SQLITester
from testers.xss_tester import XSSTester
from testers.command_injection_tester import CommandInjectionTester
from testers.fuzzing_tester import FuzzingTester
from testers.sensitive_data_tester import SensitiveDataTester
from utils.report_generator import ReportGenerator
from utils.config_validator import ConfigValidator

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class ChatGuard:
    """Main ChatGuard security testing orchestrator."""
    
    def __init__(self, config_path):
        """Initialize ChatGuard with configuration."""
        self.config_path = config_path
        self.config = self._load_config()
        self.report_generator = ReportGenerator()
        self.testers = {
            'sqli': SQLITester(self.config),
            'xss': XSSTester(self.config),
            'command_injection': CommandInjectionTester(self.config),
            'fuzzing': FuzzingTester(self.config),
            'sensitive_data': SensitiveDataTester(self.config)
        }
    
    def _load_config(self):
        """Load and validate configuration from YAML file."""
        try:
            with open(self.config_path, 'r') as file:
                config = yaml.safe_load(file)
            
            # Validate configuration
            validator = ConfigValidator()
            if not validator.validate(config):
                print(f"{Fore.RED}Configuration validation failed!")
                sys.exit(1)
            
            return config
        except FileNotFoundError:
            print(f"{Fore.RED}Configuration file not found: {self.config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"{Fore.RED}Error parsing YAML configuration: {e}")
            sys.exit(1)
    
    def run_test(self, test_name):
        """Run a specific test."""
        if test_name not in self.testers:
            print(f"{Fore.RED}Unknown test: {test_name}")
            print(f"{Fore.YELLOW}Available tests: {', '.join(self.testers.keys())}")
            return
        
        print(f"{Fore.CYAN}Running {test_name} test...")
        tester = self.testers[test_name]
        results = tester.run()
        self.report_generator.add_results(test_name, results)
    
    def run_all_tests(self):
        """Run all available security tests."""
        print(f"{Fore.GREEN}Starting ChatGuard security scan...")
        print(f"{Fore.BLUE}Target: {self.config['api_endpoint']}")
        print("-" * 60)
        
        for test_name in self.testers:
            self.run_test(test_name)
            print()  # Add spacing between tests
    
    def generate_report(self):
        """Generate and save the final report."""
        print(f"{Fore.CYAN}Generating security report...")
        self.report_generator.generate_console_report()
        self.report_generator.generate_markdown_report()
        print(f"{Fore.GREEN}Report saved to: report.md")

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ChatGuard - Automated Chatbot Security Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --config config.yaml                    # Run all tests
  python main.py --config config.yaml --test sqli        # Run only SQL injection tests
  python main.py --config config.yaml --test xss         # Run only XSS tests
        """
    )
    
    parser.add_argument(
        '--config',
        required=True,
        help='Path to the configuration YAML file'
    )
    
    parser.add_argument(
        '--test',
        choices=['sqli', 'xss', 'command_injection', 'fuzzing', 'sensitive_data'],
        help='Run only a specific test (default: run all tests)'
    )
    
    args = parser.parse_args()
    
    # Initialize ChatGuard
    chatguard = ChatGuard(args.config)
    
    # Run tests
    if args.test:
        chatguard.run_test(args.test)
    else:
        chatguard.run_all_tests()
    
    # Generate report
    chatguard.generate_report()

if __name__ == "__main__":
    main()