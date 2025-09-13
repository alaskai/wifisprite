import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import json
from datetime import datetime

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from network_scanner import NetworkScanner
from security_analyzer import SecurityAnalyzer
from report_generator import ReportGenerator
from honeypot_detector import HoneypotDetector
from host_scanner import HostScanner
from ssl_analyzer import SSLAnalyzer
from dns_analyzer import DNSAnalyzer
from advanced_report_generator import AdvancedReportGenerator
import re

class WiFiSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Security Analyzer - WiFi Sprite")
        self.root.geometry("800x700")
        
        self.scanner = NetworkScanner()
        self.analyzer = SecurityAnalyzer()
        self.reporter = ReportGenerator()
        self.honeypot_detector = HoneypotDetector()
        self.host_scanner = HostScanner()
        self.ssl_analyzer = SSLAnalyzer()
        self.dns_analyzer = DNSAnalyzer()
        self.advanced_reporter = AdvancedReportGenerator()
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="WiFi Security Analyzer - WiFi Sprite", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Current network frame
        current_frame = ttk.LabelFrame(main_frame, text="Current Network", padding="10")
        current_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.current_network_label = ttk.Label(current_frame, text="No network detected")
        self.current_network_label.grid(row=0, column=0, sticky=tk.W)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Simple Test Tab
        self.simple_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.simple_frame, text="Simple Test")
        self.setup_simple_tab()
        
        # Advanced Test Tab
        self.advanced_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.advanced_frame, text="Advanced Test")
        self.setup_advanced_tab()
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
    def setup_simple_tab(self):
        """Setup the simple test tab"""
        # Scan button
        scan_frame = ttk.Frame(self.simple_frame, padding="10")
        scan_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        self.simple_scan_button = ttk.Button(scan_frame, text="Run Basic Security Scan", 
                                           command=self.run_simple_scan)
        self.simple_scan_button.grid(row=0, column=0, padx=(0, 10))
        
        ttk.Label(scan_frame, text="Quick WiFi security check").grid(row=0, column=1, sticky=tk.W)
        
        # Progress bar
        self.simple_progress = ttk.Progressbar(self.simple_frame, mode='indeterminate')
        self.simple_progress.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=10, pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(self.simple_frame, text="Basic Security Results", padding="10")
        results_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=5)
        
        # Risk indicator
        self.simple_risk_label = ttk.Label(results_frame, text="Security Status: Unknown", 
                                         font=('Arial', 12, 'bold'))
        self.simple_risk_label.grid(row=0, column=0, pady=(0, 10))
        
        # Results text
        self.simple_results_text = scrolledtext.ScrolledText(results_frame, height=15, width=70)
        self.simple_results_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Buttons
        simple_buttons = ttk.Frame(self.simple_frame)
        simple_buttons.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(simple_buttons, text="Save Report", 
                  command=lambda: self.save_report('simple')).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(simple_buttons, text="Clear", 
                  command=self.clear_simple_results).grid(row=0, column=1)
        
        # Configure weights
        self.simple_frame.columnconfigure(0, weight=1)
        self.simple_frame.rowconfigure(2, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)
        
    def setup_advanced_tab(self):
        """Setup the advanced test tab"""
        # Control frame
        control_frame = ttk.LabelFrame(self.advanced_frame, text="Advanced Security Tests", padding="10")
        control_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=10, pady=5)
        
        # Test options
        self.honeypot_var = tk.BooleanVar(value=True)
        self.host_scan_var = tk.BooleanVar(value=True)
        self.ssl_scan_var = tk.BooleanVar(value=True)
        self.dns_scan_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(control_frame, text="Honeypot Detection (Recommended)", 
                       variable=self.honeypot_var).grid(row=0, column=0, sticky=tk.W)
        ttk.Checkbutton(control_frame, text="Network Host Discovery", 
                       variable=self.host_scan_var).grid(row=1, column=0, sticky=tk.W)
        ttk.Checkbutton(control_frame, text="SSL/Certificate Analysis", 
                       variable=self.ssl_scan_var).grid(row=2, column=0, sticky=tk.W)
        ttk.Checkbutton(control_frame, text="DNS Security Testing", 
                       variable=self.dns_scan_var).grid(row=3, column=0, sticky=tk.W)
        
        # Scan button
        self.advanced_scan_button = ttk.Button(control_frame, text="Run Advanced Security Scan", 
                                             command=self.run_advanced_scan)
        self.advanced_scan_button.grid(row=4, column=0, pady=(10, 0))
        
        # Progress bar
        self.advanced_progress = ttk.Progressbar(self.advanced_frame, mode='indeterminate')
        self.advanced_progress.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=10, pady=5)
        
        # Status label
        self.status_label = ttk.Label(self.advanced_frame, text="Ready to scan")
        self.status_label.grid(row=2, column=0, columnspan=2, padx=10)
        
        # Results frame
        results_frame = ttk.LabelFrame(self.advanced_frame, text="Advanced Security Results", padding="10")
        results_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=5)
        
        # Risk indicator
        self.advanced_risk_label = ttk.Label(results_frame, text="Security Status: Unknown", 
                                           font=('Arial', 12, 'bold'))
        self.advanced_risk_label.grid(row=0, column=0, pady=(0, 10))
        
        # Results text
        self.advanced_results_text = scrolledtext.ScrolledText(results_frame, height=12, width=70)
        self.advanced_results_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Buttons
        advanced_buttons = ttk.Frame(self.advanced_frame)
        advanced_buttons.grid(row=4, column=0, columnspan=2, pady=10)
        
        ttk.Button(advanced_buttons, text="Save Technical Report", 
                  command=lambda: self.save_report('advanced')).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(advanced_buttons, text="Clear", 
                  command=self.clear_advanced_results).grid(row=0, column=1, padx=(0, 10))
        ttk.Button(advanced_buttons, text="Help", 
                  command=self.show_help).grid(row=0, column=2)
        
        # Configure weights
        self.advanced_frame.columnconfigure(0, weight=1)
        self.advanced_frame.rowconfigure(3, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)
        
    def run_simple_scan(self):
        """Run basic security scan"""
        self.simple_scan_button.config(state='disabled')
        self.simple_progress.start()
        
        thread = threading.Thread(target=self._perform_simple_analysis)
        thread.daemon = True
        thread.start()
        
    def run_advanced_scan(self):
        """Run advanced security scan"""
        self.advanced_scan_button.config(state='disabled')
        self.advanced_progress.start()
        self.status_label.config(text="Running advanced security tests...")
        
        thread = threading.Thread(target=self._perform_advanced_analysis)
        thread.daemon = True
        thread.start()
        
    def _perform_simple_analysis(self):
        """Perform basic network analysis"""
        try:
            current_network = self.scanner.get_current_network()
            
            if not current_network:
                self._update_simple_ui_safe("No active WiFi connection detected. Please connect to a WiFi network first.")
                return
            
            network_name = current_network.get('ssid', 'Unknown')
            self._update_current_network_safe(f"Connected: {network_name}")
            
            # Basic security analysis
            analysis = self.analyzer.analyze_network_security(current_network)
            portal_info = self.analyzer.check_captive_portal()
            analysis['captive_portal'] = portal_info
            
            # Generate basic report
            report = self.reporter.generate_summary_report(current_network, analysis)
            
            self._update_simple_results_safe(current_network, analysis, report)
            
        except Exception as e:
            self._update_simple_ui_safe(f"Error during analysis: {str(e)}")
        finally:
            self._stop_simple_progress_safe()
            
    def _perform_advanced_analysis(self):
        """Perform comprehensive advanced analysis"""
        try:
            current_network = self.scanner.get_current_network()
            
            if not current_network:
                self._update_advanced_ui_safe("No active WiFi connection detected. Please connect to a WiFi network first.")
                return
            
            network_name = current_network.get('ssid', 'Unknown')
            self._update_current_network_safe(f"Analyzing: {network_name}")
            
            # Basic analysis first
            self._update_status_safe("Running basic security analysis...")
            analysis = self.analyzer.analyze_network_security(current_network)
            portal_info = self.analyzer.check_captive_portal()
            analysis['captive_portal'] = portal_info
            
            # Advanced tests
            advanced_results = {}
            
            if self.honeypot_var.get():
                self._update_status_safe("Detecting honeypots and fake access points...")
                honeypot_results = self.honeypot_detector.detect_honeypot(current_network)
                advanced_results['honeypot'] = honeypot_results
                
            if self.host_scan_var.get():
                self._update_status_safe("Scanning network hosts (discrete mode)...")
                host_results = self.host_scanner.scan_network(scan_type='discrete')
                advanced_results['hosts'] = host_results
                
            if self.ssl_scan_var.get():
                self._update_status_safe("Analyzing SSL certificates and security...")
                ssl_results = self._perform_ssl_analysis()
                advanced_results['ssl'] = ssl_results
                
            if self.dns_scan_var.get():
                self._update_status_safe("Testing DNS security and integrity...")
                dns_results = self._perform_dns_analysis()
                advanced_results['dns'] = dns_results
                
            # Combine all results
            analysis['advanced'] = advanced_results
            
            # Generate comprehensive report
            report = self._generate_advanced_report(current_network, analysis)
            
            self._update_advanced_results_safe(current_network, analysis, report)
            
        except Exception as e:
            self._update_advanced_ui_safe(f"Error during advanced analysis: {str(e)}")
        finally:
            self._stop_advanced_progress_safe()
    
    def _update_ui_safe(self, message):
        """Thread-safe UI update"""
        self.root.after(0, lambda: self._update_ui(message))
    
    def _update_ui(self, message):
        """Update UI with message"""
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, message)
        self.progress.stop()
        self.scan_button.config(state='normal')
    
    def _update_current_network_safe(self, text):
        """Thread-safe current network label update"""
        self.root.after(0, lambda: self.current_network_label.config(text=text))
    
    def _update_results_safe(self, network_info, analysis, report):
        """Thread-safe results update"""
        self.root.after(0, lambda: self._update_results(network_info, analysis, report))
    
    def _update_results(self, network_info, analysis, report):
        """Update results display"""
        # Update current network display
        network_name = network_info.get('ssid', 'Unknown')
        self.current_network_label.config(text=f"Current Network: {network_name}")
        
        # Update risk indicator
        risk_level = analysis['overall_risk']
        risk_colors = {
            'HIGH': 'red',
            'MEDIUM': 'orange', 
            'LOW': 'yellow',
            'MINIMAL': 'green'
        }
        
        self.risk_label.config(text=f"Security Status: {risk_level} RISK", 
                              foreground=risk_colors.get(risk_level, 'black'))
        
        # Update results text
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, report)
        
        # Store current analysis for saving
        self.current_analysis = {
            'network': network_info,
            'analysis': analysis,
            'report': report
        }
    
    def _stop_progress_safe(self):
        """Thread-safe progress stop"""
        self.root.after(0, self._stop_progress)
    
    def _stop_progress(self):
        """Stop progress bar and re-enable button"""
        self.progress.stop()
        self.scan_button.config(state='normal')
    
    def save_report(self):
        """Save the current analysis report"""
        if not hasattr(self, 'current_analysis'):
            messagebox.showwarning("No Report", "No analysis report to save. Please run an analysis first.")
            return
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"wifi_security_report_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.current_analysis['report'])
            
            # Also save JSON version
            json_filename = f"wifi_security_report_{timestamp}.json"
            json_report = self.reporter.generate_json_report(
                self.current_analysis['network'], 
                self.current_analysis['analysis']
            )
            
            with open(json_filename, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2)
            
            messagebox.showinfo("Report Saved", 
                              f"Reports saved as:\n{filename}\n{json_filename}")
            
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save report: {str(e)}")
    
    def clear_results(self):
        """Clear the results display"""
        self.results_text.delete(1.0, tk.END)
        self.risk_label.config(text="Security Status: Unknown", foreground='black')
        self.current_network_label.config(text="No network detected")
        if hasattr(self, 'current_analysis'):
            del self.current_analysis
    
    def show_help(self):
        """Show help information"""
        help_text = """
WiFi Sprite - WiFi Security Analyzer

This tool analyzes your current WiFi connection for security risks.

Features:
• Encryption detection (WEP/WPA/WPA2/WPA3)
• Risk assessment with color-coded ratings
• Captive portal detection
• Educational security explanations

Usage:
1. Connect to a WiFi network
2. Click 'Analyze Current Network'
3. Review the security report
4. Save reports for reference

Security Ratings:
🔴 HIGH RISK - Avoid sensitive activities
🟠 MEDIUM RISK - Use VPN, be cautious  
🟡 LOW RISK - Generally safe with precautions
🟢 MINIMAL RISK - Secure network

This tool is for educational purposes only.
Use responsibly and ethically.
        """
        messagebox.showinfo("Help - WiFi Sprite", help_text)
    
    def _generate_advanced_report(self, network_info, analysis_results):
        return self.advanced_reporter.generate_advanced_report(network_info, analysis_results)
    
    def _update_simple_ui_safe(self, message):
        self.root.after(0, lambda: self._update_simple_ui(message))
    
    def _update_simple_ui(self, message):
        self.simple_results_text.delete(1.0, tk.END)
        self.simple_results_text.insert(tk.END, message)
        self.simple_progress.stop()
        self.simple_scan_button.config(state='normal')
    
    def _update_simple_results_safe(self, network_info, analysis, report):
        self.root.after(0, lambda: self._update_simple_results(network_info, analysis, report))
    
    def _update_simple_results(self, network_info, analysis, report):
        risk_level = analysis['overall_risk']
        risk_colors = {'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow', 'MINIMAL': 'green'}
        self.simple_risk_label.config(text=f"Security Status: {risk_level} RISK", 
                                     foreground=risk_colors.get(risk_level, 'black'))
        self.simple_results_text.delete(1.0, tk.END)
        self.simple_results_text.insert(tk.END, report)
        self.current_simple_analysis = {'network': network_info, 'analysis': analysis, 'report': report}
    
    def _stop_simple_progress_safe(self):
        self.root.after(0, self._stop_simple_progress)
    
    def _stop_simple_progress(self):
        self.simple_progress.stop()
        self.simple_scan_button.config(state='normal')
    
    def _update_advanced_ui_safe(self, message):
        self.root.after(0, lambda: self._update_advanced_ui(message))
    
    def _update_advanced_ui(self, message):
        self.advanced_results_text.delete(1.0, tk.END)
        self.advanced_results_text.insert(tk.END, message)
        self.advanced_progress.stop()
        self.advanced_scan_button.config(state='normal')
        self.status_label.config(text="Scan completed")
    
    def _update_advanced_results_safe(self, network_info, analysis, report):
        self.root.after(0, lambda: self._update_advanced_results(network_info, analysis, report))
    
    def _update_advanced_results(self, network_info, analysis, report):
        advanced_results = analysis.get('advanced', {})
        risk_level = analysis['overall_risk']
        if 'honeypot' in advanced_results and advanced_results['honeypot'].get('is_honeypot'):
            risk_level = 'CRITICAL'
        risk_colors = {'CRITICAL': 'red', 'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow', 'MINIMAL': 'green'}
        self.advanced_risk_label.config(text=f"Security Status: {risk_level} RISK", 
                                       foreground=risk_colors.get(risk_level, 'black'))
        self.advanced_results_text.delete(1.0, tk.END)
        self.advanced_results_text.insert(tk.END, report)
        self.current_advanced_analysis = {'network': network_info, 'analysis': analysis, 'report': report}
    
    def _stop_advanced_progress_safe(self):
        self.root.after(0, self._stop_advanced_progress)
    
    def _stop_advanced_progress(self):
        self.advanced_progress.stop()
        self.advanced_scan_button.config(state='normal')
        self.status_label.config(text="Ready to scan")
    
    def _update_status_safe(self, message):
        self.root.after(0, lambda: self.status_label.config(text=message))
    
    def _update_current_network_safe(self, text):
        self.root.after(0, lambda: self.current_network_label.config(text=text))
    
    def clear_simple_results(self):
        self.simple_results_text.delete(1.0, tk.END)
        self.simple_risk_label.config(text="Security Status: Unknown", foreground='black')
        if hasattr(self, 'current_simple_analysis'):
            del self.current_simple_analysis
    
    def clear_advanced_results(self):
        self.advanced_results_text.delete(1.0, tk.END)
        self.advanced_risk_label.config(text="Security Status: Unknown", foreground='black')
        self.status_label.config(text="Ready to scan")
        if hasattr(self, 'current_advanced_analysis'):
            del self.current_advanced_analysis
    
    def save_report(self, report_type='simple'):
        if report_type == 'simple':
            if not hasattr(self, 'current_simple_analysis'):
                messagebox.showwarning("No Report", "No simple analysis report to save.")
                return
            analysis_data = self.current_simple_analysis
            prefix = "basic"
        else:
            if not hasattr(self, 'current_advanced_analysis'):
                messagebox.showwarning("No Report", "No advanced analysis report to save.")
                return
            analysis_data = self.current_advanced_analysis
            prefix = "advanced"
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"wifi_{prefix}_report_{timestamp}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(analysis_data['report'])
            messagebox.showinfo("Report Saved", f"Report saved as: {filename}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save report: {str(e)}")
    
    def _perform_ssl_analysis(self):
        """Perform SSL/TLS security analysis"""
        try:
            return self.ssl_analyzer.analyze_ssl_security()
        except Exception as e:
            return {
                'error': str(e),
                'certificates': [],
                'vulnerabilities': [],
                'security_issues': [],
                'recommendations': ['SSL analysis failed - check network connection']
            }
    
    def _perform_dns_analysis(self):
        """Perform DNS security analysis"""
        try:
            return self.dns_analyzer.analyze_dns_security()
        except Exception as e:
            return {
                'error': str(e),
                'dns_hijacking': [],
                'dns_filtering': [],
                'dns_performance': {},
                'security_issues': [],
                'recommendations': ['DNS analysis failed - check network connection']
            }

def main():
    """Main entry point for the application"""
    root = tk.Tk()
    app = WiFiSecurityTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()