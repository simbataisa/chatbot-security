"""
Report generator module for creating security scan reports.
"""

import json
import time
from pathlib import Path
from colorama import Fore, Style

class ReportGenerator:
    """Generates security scan reports in console and Markdown formats."""
    
    def __init__(self):
        """Initialize the report generator."""
        self.all_results = {}
        self.scan_start_time = time.strftime('%Y-%m-%d %H:%M:%S')
    
    def add_results(self, test_name, results):
        """Add test results to the report."""
        self.all_results[test_name] = results
    
    def generate_console_report(self):
        """Generate and display a console report."""
        print("\n" + "=" * 80)
        print(f"{Fore.CYAN}{Style.BRIGHT}CHATGUARD SECURITY SCAN REPORT")
        print("=" * 80)
        print(f"{Fore.WHITE}Scan completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Scan started at: {self.scan_start_time}")
        print()
        
        total_findings = 0
        high_risk = 0
        medium_risk = 0
        low_risk = 0
        
        # Count findings by severity
        for test_name, results in self.all_results.items():
            total_findings += len(results)
            for result in results:
                severity = result.get('severity', 'Medium')
                if severity == 'High':
                    high_risk += 1
                elif severity == 'Medium':
                    medium_risk += 1
                else:
                    low_risk += 1
        
        # Summary
        print(f"{Fore.YELLOW}{Style.BRIGHT}SUMMARY:")
        print(f"{Fore.WHITE}Total findings: {total_findings}")
        print(f"{Fore.RED}High risk: {high_risk}")
        print(f"{Fore.YELLOW}Medium risk: {medium_risk}")
        print(f"{Fore.BLUE}Low risk: {low_risk}")
        print()
        
        # Detailed findings by test
        for test_name, results in self.all_results.items():
            print(f"{Fore.CYAN}{Style.BRIGHT}{test_name.upper()} TEST RESULTS:")
            print("-" * 60)
            
            if not results:
                print(f"{Fore.GREEN}No vulnerabilities found")
            else:
                for i, result in enumerate(results, 1):
                    severity = result.get('severity', 'Medium')
                    color = Fore.RED if severity == 'High' else Fore.YELLOW if severity == 'Medium' else Fore.BLUE
                    
                    print(f"{color}[{severity}] Finding #{i}")
                    print(f"{Fore.WHITE}Type: {result.get('vulnerability_type', 'Unknown')}")
                    print(f"Payload: {result.get('payload', 'N/A')[:100]}{'...' if len(result.get('payload', '')) > 100 else ''}")
                    print(f"Reason: {result.get('reason', 'N/A')}")
                    print(f"Timestamp: {result.get('timestamp', 'N/A')}")
                    print()
            
            print()
    
    def generate_markdown_report(self, filename='report.md'):
        """Generate a Markdown report file."""
        report_content = self._build_markdown_content()
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"{Fore.GREEN}Markdown report saved to: {filename}")
        except Exception as e:
            print(f"{Fore.RED}Error saving Markdown report: {e}")
    
    def _build_markdown_content(self):
        """Build the Markdown report content."""
        content = []
        
        # Header
        content.append("# ChatGuard Security Scan Report")
        content.append("")
        content.append(f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}")
        content.append(f"**Scan Started:** {self.scan_start_time}")
        content.append("")
        
        # Summary
        total_findings = sum(len(results) for results in self.all_results.values())
        high_risk = sum(1 for results in self.all_results.values() for result in results if result.get('severity') == 'High')
        medium_risk = sum(1 for results in self.all_results.values() for result in results if result.get('severity') == 'Medium')
        low_risk = sum(1 for results in self.all_results.values() for result in results if result.get('severity') == 'Low')
        
        content.append("## Executive Summary")
        content.append("")
        content.append(f"- **Total Findings:** {total_findings}")
        content.append(f"- **High Risk:** {high_risk}")
        content.append(f"- **Medium Risk:** {medium_risk}")
        content.append(f"- **Low Risk:** {low_risk}")
        content.append("")
        
        if total_findings == 0:
            content.append("🎉 **No security vulnerabilities were detected during this scan.**")
            content.append("")
        else:
            content.append("⚠️ **Security vulnerabilities were detected. Please review the findings below.**")
            content.append("")
        
        # Risk Level Definitions
        content.append("## Risk Level Definitions")
        content.append("")
        content.append("| Risk Level | Description |")
        content.append("|------------|-------------|")
        content.append("| **High** | Critical vulnerabilities that could lead to immediate compromise |")
        content.append("| **Medium** | Significant vulnerabilities that could be exploited with moderate effort |")
        content.append("| **Low** | Minor issues that may provide limited information to attackers |")
        content.append("")
        
        # Detailed findings
        content.append("## Detailed Findings")
        content.append("")
        
        finding_number = 1
        for test_name, results in self.all_results.items():
            content.append(f"### {test_name.replace('_', ' ').title()} Test")
            content.append("")
            
            if not results:
                content.append("✅ **No vulnerabilities found**")
                content.append("")
            else:
                for result in results:
                    severity = result.get('severity', 'Medium')
                    emoji = "🔴" if severity == 'High' else "🟡" if severity == 'Medium' else "🔵"
                    
                    content.append(f"#### {emoji} Finding #{finding_number}: {result.get('vulnerability_type', 'Unknown Vulnerability')}")
                    content.append("")
                    content.append(f"**Severity:** {severity}")
                    content.append(f"**Timestamp:** {result.get('timestamp', 'N/A')}")
                    content.append("")
                    content.append("**Description:**")
                    content.append(f"{result.get('reason', 'No description available')}")
                    content.append("")
                    content.append("**Payload:**")
                    content.append("```")
                    content.append(result.get('payload', 'N/A'))
                    content.append("```")
                    content.append("")
                    
                    # Response details (truncated for readability)
                    response = result.get('response', {})
                    if isinstance(response, dict):
                        content.append("**Response Details:**")
                        content.append(f"- Status Code: {response.get('status_code', 'N/A')}")
                        content.append(f"- Response Time: {response.get('response_time', 'N/A')}s")
                        
                        response_body = response.get('response_body', '')
                        if response_body:
                            # Truncate long responses
                            if len(response_body) > 500:
                                response_body = response_body[:500] + "... (truncated)"
                            content.append("")
                            content.append("**Response Body (truncated):**")
                            content.append("```")
                            content.append(response_body)
                            content.append("```")
                    
                    content.append("")
                    content.append("---")
                    content.append("")
                    finding_number += 1
        
        # Recommendations
        content.append("## Recommendations")
        content.append("")
        
        if high_risk > 0:
            content.append("### 🔴 High Priority Actions")
            content.append("1. **Immediate Action Required:** Address all high-risk vulnerabilities immediately")
            content.append("2. **Input Validation:** Implement proper input validation and sanitization")
            content.append("3. **Output Encoding:** Ensure all user input is properly encoded in responses")
            content.append("4. **Security Review:** Conduct a comprehensive security code review")
            content.append("")
        
        if medium_risk > 0:
            content.append("### 🟡 Medium Priority Actions")
            content.append("1. **Security Hardening:** Implement additional security controls")
            content.append("2. **Error Handling:** Improve error handling to prevent information disclosure")
            content.append("3. **Monitoring:** Implement security monitoring and logging")
            content.append("")
        
        if low_risk > 0:
            content.append("### 🔵 Low Priority Actions")
            content.append("1. **Information Disclosure:** Review and minimize information disclosure")
            content.append("2. **Security Headers:** Implement appropriate security headers")
            content.append("3. **Documentation:** Update security documentation and procedures")
            content.append("")
        
        content.append("### General Recommendations")
        content.append("1. **Regular Testing:** Perform regular security testing")
        content.append("2. **Security Training:** Provide security training for development team")
        content.append("3. **Incident Response:** Establish incident response procedures")
        content.append("4. **Penetration Testing:** Consider professional penetration testing")
        content.append("")
        
        # Footer
        content.append("---")
        content.append("")
        content.append("*Report generated by ChatGuard - Automated Chatbot Security Testing Tool*")
        content.append("")
        
        return "\n".join(content)
    
    def export_json(self, filename='report.json'):
        """Export results as JSON for further processing."""
        report_data = {
            'scan_info': {
                'start_time': self.scan_start_time,
                'end_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'tool': 'ChatGuard',
                'version': '1.0'
            },
            'summary': {
                'total_findings': sum(len(results) for results in self.all_results.values()),
                'high_risk': sum(1 for results in self.all_results.values() for result in results if result.get('severity') == 'High'),
                'medium_risk': sum(1 for results in self.all_results.values() for result in results if result.get('severity') == 'Medium'),
                'low_risk': sum(1 for results in self.all_results.values() for result in results if result.get('severity') == 'Low')
            },
            'findings': self.all_results
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            print(f"{Fore.GREEN}JSON report saved to: {filename}")
        except Exception as e:
            print(f"{Fore.RED}Error saving JSON report: {e}")