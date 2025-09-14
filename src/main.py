import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import json
from datetime import datetime
from tkinter import font
from PIL import Image, ImageTk

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
from port_scanner import PortScanner
from advanced_report_generator import AdvancedReportGenerator
from safe_scanner import SafeScanner
import re

class WiFiSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Security Analyzer - WiFi Sprite")
        self.root.geometry("900x750")
        
        # Set window icon
        self._set_window_icon()
        
        # Configure dark theme
        self._setup_dark_theme()
        
        # Define colors
        self.colors = {
            'bg_dark': '#2b2b2b',
            'bg_medium': '#3c3c3c', 
            'bg_light': '#4d4d4d',
            'text_light': '#ffffff',
            'text_gray': '#cccccc',
            'accent': '#0078d4',
            'success': '#107c10',
            'warning': '#ff8c00',
            'error': '#d13438',
            'critical': '#8b0000'
        }
        
        self.scanner = NetworkScanner()
        self.analyzer = SecurityAnalyzer()
        self.reporter = ReportGenerator()
        self.honeypot_detector = HoneypotDetector()
        self.host_scanner = HostScanner()
        self.ssl_analyzer = SSLAnalyzer()
        self.dns_analyzer = DNSAnalyzer()
        self.port_scanner = PortScanner()
        self.advanced_reporter = AdvancedReportGenerator()
        self.safe_scanner = SafeScanner()
        
        self.setup_ui()
    
    def _setup_dark_theme(self):
        """Configure dark theme for the application"""
        style = ttk.Style()
        
        # Configure dark theme
        style.theme_use('clam')
        
        # Configure colors
        style.configure('TFrame', background='#2b2b2b')
        style.configure('TLabel', background='#2b2b2b', foreground='#ffffff')
        style.configure('TButton', background='#4d4d4d', foreground='#ffffff')
        style.configure('TCheckbutton', background='#2b2b2b', foreground='#ffffff')
        style.configure('TLabelFrame', background='#2b2b2b', foreground='#ffffff')
        style.configure('TLabelFrame.Label', background='#2b2b2b', foreground='#ffffff')
        style.configure('TNotebook', background='#3c3c3c')
        style.configure('TNotebook.Tab', background='#4d4d4d', foreground='#ffffff')
        style.configure('TProgressbar', background='#0078d4')
        
        # Configure root window
        self.root.configure(bg='#2b2b2b')
        
        # Map hover states
        style.map('TButton',
                 background=[('active', '#5d5d5d'), ('pressed', '#6d6d6d')])
        style.map('TNotebook.Tab',
                 background=[('selected', '#0078d4'), ('active', '#5d5d5d')])
    
    def _set_window_icon(self):
        """Set the window icon from the assets folder"""
        try:
            icon_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'image.png')
            if os.path.exists(icon_path):
                # Load and resize icon for window
                icon_image = Image.open(icon_path)
                icon_image = icon_image.resize((32, 32), Image.Resampling.LANCZOS)
                icon_photo = ImageTk.PhotoImage(icon_image)
                self.root.iconphoto(True, icon_photo)
                
                # Store reference to prevent garbage collection
                self.icon_photo = icon_photo
        except Exception:
            pass  # Silently fail if icon can't be loaded
    
    def _add_logo(self, parent_frame):
        """Add logo to the header frame"""
        try:
            logo_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'image.png')
            if os.path.exists(logo_path):
                # Load and resize logo for header
                logo_image = Image.open(logo_path)
                logo_image = logo_image.resize((48, 48), Image.Resampling.LANCZOS)
                logo_photo = ImageTk.PhotoImage(logo_image)
                
                # Create logo label
                logo_label = ttk.Label(parent_frame, image=logo_photo)
                logo_label.grid(row=0, column=0)
                
                # Store reference to prevent garbage collection
                self.logo_photo = logo_photo
        except Exception:
            pass  # Silently fail if logo can't be loaded
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Logo and Title frame
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Add logo if available
        self._add_logo(header_frame)
        
        # Title
        title_label = ttk.Label(header_frame, text="WiFi Security Analyzer - WiFi Sprite", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=1, padx=(10, 0))
        
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
        
        # Safe Scan Tab
        self.safe_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.safe_frame, text="🛡️ Safe Scan")
        self.setup_safe_tab()
        
        # Network Log Tab
        self.log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.log_frame, text="📋 Network Log")
        self.setup_log_tab()
        
        # Security Score Tab
        self.score_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.score_frame, text="🏆 Security Score")
        self.setup_score_tab()
        
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
        
        # Results text with dark theme
        self.simple_results_text = tk.Text(results_frame, height=15, width=70,
                                          bg='#1e1e1e', fg='#ffffff', 
                                          insertbackground='#ffffff',
                                          selectbackground='#0078d4',
                                          font=('Consolas', 10),
                                          wrap=tk.WORD)
        
        # Add scrollbar
        simple_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.simple_results_text.yview)
        self.simple_results_text.configure(yscrollcommand=simple_scrollbar.set)
        
        self.simple_results_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        simple_scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        
        # Configure text tags for colors
        self._configure_text_tags(self.simple_results_text)
        
        # Buttons
        simple_buttons = ttk.Frame(self.simple_frame)
        simple_buttons.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(simple_buttons, text="Save Report", 
                  command=lambda: self.save_report('simple')).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(simple_buttons, text="Log Network Details", 
                  command=self.log_simple_network).grid(row=0, column=1, padx=(0, 10))
        ttk.Button(simple_buttons, text="Clear", 
                  command=self.clear_simple_results).grid(row=0, column=2)
        
        # Configure weights
        self.simple_frame.columnconfigure(0, weight=1)
        self.simple_frame.rowconfigure(2, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)
    
    def _configure_text_tags(self, text_widget):
        """Configure color tags for text widget"""
        text_widget.tag_configure('critical', foreground='#ff4444', font=('Consolas', 10, 'bold'))
        text_widget.tag_configure('high', foreground='#ff8800', font=('Consolas', 10, 'bold'))
        text_widget.tag_configure('medium', foreground='#ffaa00', font=('Consolas', 10, 'bold'))
        text_widget.tag_configure('low', foreground='#88dd88', font=('Consolas', 10, 'bold'))
        text_widget.tag_configure('minimal', foreground='#44ff44', font=('Consolas', 10, 'bold'))
        text_widget.tag_configure('header', foreground='#66ccff', font=('Consolas', 11, 'bold'))
        text_widget.tag_configure('subheader', foreground='#aaccff', font=('Consolas', 10, 'bold'))
        text_widget.tag_configure('warning', foreground='#ffcc44', font=('Consolas', 10, 'bold'))
        text_widget.tag_configure('success', foreground='#44ff88', font=('Consolas', 10, 'bold'))
        text_widget.tag_configure('info', foreground='#88ccff')
        text_widget.tag_configure('emphasis', foreground='#ffffff', font=('Consolas', 10, 'bold'))
        
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
        self.port_scan_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(control_frame, text="Honeypot Detection (Recommended)", 
                       variable=self.honeypot_var).grid(row=0, column=0, sticky=tk.W)
        ttk.Checkbutton(control_frame, text="Network Host Discovery", 
                       variable=self.host_scan_var).grid(row=1, column=0, sticky=tk.W)
        ttk.Checkbutton(control_frame, text="SSL/Certificate Analysis", 
                       variable=self.ssl_scan_var).grid(row=2, column=0, sticky=tk.W)
        ttk.Checkbutton(control_frame, text="DNS Security Testing", 
                       variable=self.dns_scan_var).grid(row=3, column=0, sticky=tk.W)
        ttk.Checkbutton(control_frame, text="Port Security Scanning", 
                       variable=self.port_scan_var).grid(row=4, column=0, sticky=tk.W)
        
        # Scan button
        self.advanced_scan_button = ttk.Button(control_frame, text="Run Advanced Security Scan", 
                                             command=self.run_advanced_scan)
        self.advanced_scan_button.grid(row=5, column=0, pady=(10, 0))
        
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
        
        # Results text with dark theme
        self.advanced_results_text = tk.Text(results_frame, height=12, width=70,
                                            bg='#1e1e1e', fg='#ffffff',
                                            insertbackground='#ffffff',
                                            selectbackground='#0078d4',
                                            font=('Consolas', 10),
                                            wrap=tk.WORD)
        
        # Add scrollbar
        advanced_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.advanced_results_text.yview)
        self.advanced_results_text.configure(yscrollcommand=advanced_scrollbar.set)
        
        self.advanced_results_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        advanced_scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        
        # Configure text tags for colors
        self._configure_text_tags(self.advanced_results_text)
        
        # Buttons
        advanced_buttons = ttk.Frame(self.advanced_frame)
        advanced_buttons.grid(row=4, column=0, columnspan=2, pady=10)
        
        ttk.Button(advanced_buttons, text="Save Technical Report", 
                  command=lambda: self.save_report('advanced')).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(advanced_buttons, text="Log Network Details", 
                  command=self.log_advanced_network).grid(row=0, column=1, padx=(0, 10))
        ttk.Button(advanced_buttons, text="Clear", 
                  command=self.clear_advanced_results).grid(row=0, column=2, padx=(0, 10))
        ttk.Button(advanced_buttons, text="Help", 
                  command=self.show_help).grid(row=0, column=3)
        
        # Configure weights
        self.advanced_frame.columnconfigure(0, weight=1)
        self.advanced_frame.rowconfigure(3, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)
    
    def setup_safe_tab(self):
        """Setup the safe scan tab for analyzing nearby networks without connecting"""
        # Info frame
        info_frame = ttk.LabelFrame(self.safe_frame, text="Safe Scan Mode", padding="10")
        info_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=10, pady=5)
        
        info_text = "Analyze nearby open WiFi networks WITHOUT connecting. Detects ESP32 honeypots and fake access points."
        ttk.Label(info_frame, text=info_text, wraplength=600).grid(row=0, column=0, sticky=tk.W)
        
        # Control frame
        control_frame = ttk.LabelFrame(self.safe_frame, text="Network Discovery", padding="10")
        control_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=10, pady=5)
        
        # Scan button
        self.safe_scan_button = ttk.Button(control_frame, text="Discover Nearby Open Networks", 
                                         command=self.run_safe_discovery)
        self.safe_scan_button.grid(row=0, column=0, padx=(0, 10))
        
        ttk.Label(control_frame, text="Passive scan - no connections made").grid(row=0, column=1, sticky=tk.W)
        
        # Progress bar
        self.safe_progress = ttk.Progressbar(self.safe_frame, mode='indeterminate')
        self.safe_progress.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=10, pady=5)
        
        # Networks list frame
        networks_frame = ttk.LabelFrame(self.safe_frame, text="Discovered Open Networks", padding="10")
        networks_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=5)
        
        # Networks listbox
        self.networks_listbox = tk.Listbox(networks_frame, height=8, 
                                          bg='#1e1e1e', fg='#ffffff',
                                          selectbackground='#0078d4',
                                          font=('Consolas', 10))
        networks_scrollbar = ttk.Scrollbar(networks_frame, orient=tk.VERTICAL, command=self.networks_listbox.yview)
        self.networks_listbox.configure(yscrollcommand=networks_scrollbar.set)
        
        self.networks_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        networks_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Analyze button
        ttk.Button(networks_frame, text="Analyze Selected Network", 
                  command=self.analyze_selected_network).grid(row=1, column=0, pady=(10, 0))
        
        # Results frame
        results_frame = ttk.LabelFrame(self.safe_frame, text="Quarantine Analysis Results", padding="10")
        results_frame.grid(row=3, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=5)
        
        # Safety status
        self.safe_status_label = ttk.Label(results_frame, text="No Analysis Performed", 
                                         font=('Arial', 12, 'bold'))
        self.safe_status_label.grid(row=0, column=0, pady=(0, 10))
        
        # Results text
        self.safe_results_text = tk.Text(results_frame, height=12, width=50,
                                        bg='#1e1e1e', fg='#ffffff',
                                        insertbackground='#ffffff',
                                        selectbackground='#0078d4',
                                        font=('Consolas', 9),
                                        wrap=tk.WORD)
        
        safe_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.safe_results_text.yview)
        self.safe_results_text.configure(yscrollcommand=safe_scrollbar.set)
        
        self.safe_results_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        safe_scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        
        # Configure text tags
        self._configure_text_tags(self.safe_results_text)
        
        # Buttons
        safe_buttons = ttk.Frame(self.safe_frame)
        safe_buttons.grid(row=4, column=0, columnspan=2, pady=10)
        
        ttk.Button(safe_buttons, text="Save Quarantine Report", 
                  command=lambda: self.save_report('safe')).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(safe_buttons, text="Clear Results", 
                  command=self.clear_safe_results).grid(row=0, column=1, padx=(0, 10))
        ttk.Button(safe_buttons, text="Refresh Networks", 
                  command=self.run_safe_discovery).grid(row=0, column=2, padx=(0, 10))
        ttk.Button(safe_buttons, text="Log Network Details", 
                  command=self.log_current_network).grid(row=0, column=3)
        
        # Configure weights
        self.safe_frame.columnconfigure(0, weight=1)
        self.safe_frame.columnconfigure(1, weight=1)
        self.safe_frame.rowconfigure(3, weight=1)
        networks_frame.columnconfigure(0, weight=1)
        networks_frame.rowconfigure(0, weight=1)
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
                
            if self.port_scan_var.get():
                self._update_status_safe("Scanning for dangerous open ports...")
                port_results = self._perform_port_analysis()
                advanced_results['ports'] = port_results
                
            if self.port_scan_var.get():
                self._update_status_safe("Scanning for dangerous open ports...")
                port_results = self._perform_port_analysis()
                advanced_results['ports'] = port_results
                
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

Tabs:
• Simple Test - Analyze current connection
• Advanced Test - Deep security analysis
• Safe Scan - Analyze nearby networks WITHOUT connecting

Safe Scan Mode:
• Discovers nearby open WiFi networks
• Analyzes without connecting (quarantined analysis)
• Detects ESP32/Arduino honeypots and fake access points
• Provides safety recommendations before connection

Features:
• Encryption detection (WEP/WPA/WPA2/WPA3)
• Honeypot and fake AP detection
• ESP32/Arduino device identification
• Risk assessment with color-coded ratings
• Captive portal detection

Safety Ratings:
🚨 DANGEROUS - Do not connect
⚠️ SUSPICIOUS - Use extreme caution
✅ RELATIVELY SAFE - Monitor connection

This tool is for educational and defensive purposes only.
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
        risk_colors = {'CRITICAL': '#ff4444', 'HIGH': '#ff8800', 'MEDIUM': '#ffaa00', 'LOW': '#88dd88', 'MINIMAL': '#44ff44'}
        
        # Update risk label with color
        self.simple_risk_label.config(text=f"Security Status: {risk_level} RISK", 
                                     foreground=risk_colors.get(risk_level, '#ffffff'))
        
        # Clear and insert colored text
        self.simple_results_text.delete(1.0, tk.END)
        self._insert_colored_report(self.simple_results_text, report, risk_level)
        
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
        
        risk_colors = {'CRITICAL': '#ff4444', 'HIGH': '#ff8800', 'MEDIUM': '#ffaa00', 'LOW': '#88dd88', 'MINIMAL': '#44ff44'}
        
        # Update risk label with color
        self.advanced_risk_label.config(text=f"Security Status: {risk_level} RISK", 
                                       foreground=risk_colors.get(risk_level, '#ffffff'))
        
        # Clear and insert colored text
        self.advanced_results_text.delete(1.0, tk.END)
        self._insert_colored_report(self.advanced_results_text, report, risk_level)
        
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
        elif report_type == 'safe':
            if not hasattr(self, 'current_safe_analysis'):
                messagebox.showwarning("No Report", "No safe scan report to save.")
                return
            analysis_data = self.current_safe_analysis
            prefix = "safe_scan"
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
    
    def _perform_port_analysis(self):
        """Perform port security analysis"""
        try:
            return self.port_scanner.scan_network_ports(scan_type='common', timeout=1)
        except Exception as e:
            return {
                'error': str(e),
                'open_ports': [],
                'dangerous_ports': [],
                'security_issues': [],
                'recommendations': ['Port scan failed - check network connection']
            }
    
    def _insert_colored_report(self, text_widget, report, risk_level):
        """Insert report with color formatting"""
        lines = report.split('\n')
        
        for line in lines:
            # Determine line type and apply appropriate color
            if line.startswith('='):
                text_widget.insert(tk.END, line + '\n', 'header')
            elif line.startswith('-'):
                text_widget.insert(tk.END, line + '\n', 'subheader')
            elif '🚨' in line or 'CRITICAL' in line:
                text_widget.insert(tk.END, line + '\n', 'critical')
            elif '🔴' in line or 'HIGH RISK' in line:
                text_widget.insert(tk.END, line + '\n', 'high')
            elif '🟠' in line or 'MEDIUM RISK' in line:
                text_widget.insert(tk.END, line + '\n', 'medium')
            elif '🟡' in line or 'LOW RISK' in line:
                text_widget.insert(tk.END, line + '\n', 'low')
            elif '🟢' in line or 'MINIMAL RISK' in line:
                text_widget.insert(tk.END, line + '\n', 'minimal')
            elif '✅' in line or 'SUCCESS' in line:
                text_widget.insert(tk.END, line + '\n', 'success')
            elif '⚠️' in line or 'WARNING' in line:
                text_widget.insert(tk.END, line + '\n', 'warning')
            elif line.strip().endswith(':') and not line.startswith(' '):
                text_widget.insert(tk.END, line + '\n', 'emphasis')
            elif '•' in line or '  ' in line:
                text_widget.insert(tk.END, line + '\n', 'info')
            else:
                text_widget.insert(tk.END, line + '\n')
        
        # Scroll to top
        text_widget.see(tk.INSERT)
    
    def run_safe_discovery(self):
        """Run safe network discovery"""
        self.safe_scan_button.config(state='disabled')
        self.safe_progress.start()
        
        thread = threading.Thread(target=self._perform_safe_discovery)
        thread.daemon = True
        thread.start()
    
    def _perform_safe_discovery(self):
        """Perform safe network discovery in background"""
        try:
            networks = self.safe_scanner.discover_nearby_networks()
            self._update_networks_list_safe(networks)
        except Exception as e:
            self._update_safe_ui_safe(f"Discovery error: {str(e)}")
        finally:
            self._stop_safe_progress_safe()
    
    def _update_networks_list_safe(self, networks):
        """Thread-safe update of networks list"""
        self.root.after(0, lambda: self._update_networks_list(networks))
    
    def _update_networks_list(self, networks):
        """Update the networks listbox"""
        self.networks_listbox.delete(0, tk.END)
        self.discovered_networks = networks
        
        if not networks:
            self.networks_listbox.insert(tk.END, "No open networks found")
        else:
            for i, network in enumerate(networks):
                ssid = network.get('ssid', 'Unknown')
                signal = network.get('signal_strength', 0)
                display_text = f"{ssid} (Signal: {signal}%)"
                self.networks_listbox.insert(tk.END, display_text)
    
    def analyze_selected_network(self):
        """Analyze the selected network safely"""
        selection = self.networks_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a network to analyze.")
            return
        
        if not hasattr(self, 'discovered_networks') or not self.discovered_networks:
            messagebox.showwarning("No Networks", "No networks available. Run discovery first.")
            return
        
        network_index = selection[0]
        if network_index >= len(self.discovered_networks):
            return
        
        selected_network = self.discovered_networks[network_index]
        
        # Run analysis in background
        thread = threading.Thread(target=self._perform_safe_analysis, args=(selected_network,))
        thread.daemon = True
        thread.start()
    
    def _perform_safe_analysis(self, network):
        """Perform safe analysis of selected network"""
        try:
            analysis = self.safe_scanner.analyze_network_safely(network)
            report = self.safe_scanner.get_quarantine_report(network)
            
            self._update_safe_results_safe(network, analysis, report)
        except Exception as e:
            self._update_safe_ui_safe(f"Analysis error: {str(e)}")
    
    def _update_safe_results_safe(self, network, analysis, report):
        """Thread-safe update of safe scan results"""
        self.root.after(0, lambda: self._update_safe_results(network, analysis, report))
    
    def _update_safe_results(self, network, analysis, report):
        """Update safe scan results display"""
        status = analysis.get('quarantine_status', 'Unknown')
        safety_score = analysis.get('safety_score', 0)
        
        # Update status with color coding
        if 'DANGEROUS' in status:
            color = '#ff4444'
        elif 'SUSPICIOUS' in status:
            color = '#ff8800'
        else:
            color = '#88dd88'
        
        self.safe_status_label.config(text=f"{status} (Score: {safety_score}/100)", 
                                     foreground=color)
        
        # Update results text
        self.safe_results_text.delete(1.0, tk.END)
        self._insert_colored_report(self.safe_results_text, report, status)
        
        # Store for saving
        self.current_safe_analysis = {
            'network': network,
            'analysis': analysis,
            'report': report
        }
        
        # Store current network for logging
        self.current_network_for_log = {'network': network, 'analysis': analysis}
        
        # Add points for scanning
        points = self.safe_scanner.add_scan_points(analysis)
        self.safe_status_label.config(text=f"{status} (Score: {safety_score}/100) +{points} pts", 
                                     foreground=color)
        
        # Refresh score display if tab exists
        try:
            self.refresh_score_display()
        except:
            pass
    
    def _update_safe_ui_safe(self, message):
        """Thread-safe safe scan UI update"""
        self.root.after(0, lambda: self._update_safe_ui(message))
    
    def _update_safe_ui(self, message):
        """Update safe scan UI with message"""
        self.safe_results_text.delete(1.0, tk.END)
        self.safe_results_text.insert(tk.END, message)
    
    def _stop_safe_progress_safe(self):
        """Thread-safe stop safe progress"""
        self.root.after(0, self._stop_safe_progress)
    
    def _stop_safe_progress(self):
        """Stop safe scan progress"""
        self.safe_progress.stop()
        self.safe_scan_button.config(state='normal')
    
    def clear_safe_results(self):
        """Clear safe scan results"""
        self.safe_results_text.delete(1.0, tk.END)
        self.safe_status_label.config(text="No Analysis Performed", foreground='#ffffff')
        self.networks_listbox.delete(0, tk.END)
        if hasattr(self, 'current_safe_analysis'):
            del self.current_safe_analysis
        if hasattr(self, 'discovered_networks'):
            del self.discovered_networks
    
    def setup_log_tab(self):
        """Setup the network log tab"""
        # Info frame
        info_frame = ttk.LabelFrame(self.log_frame, text="Network Logging", padding="10")
        info_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=10, pady=5)
        
        info_text = "Log and track potentially dangerous WiFi networks with MAC addresses and locations."
        ttk.Label(info_frame, text=info_text, wraplength=600).grid(row=0, column=0, sticky=tk.W)
        
        # Controls frame
        controls_frame = ttk.Frame(self.log_frame)
        controls_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=5)
        
        ttk.Button(controls_frame, text="Refresh Log", 
                  command=self.refresh_network_log).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(controls_frame, text="Clear All Logs", 
                  command=self.clear_network_log).grid(row=0, column=1, padx=(0, 10))
        ttk.Button(controls_frame, text="Export Log", 
                  command=self.export_network_log).grid(row=0, column=2)
        
        # Log display frame
        log_display_frame = ttk.LabelFrame(self.log_frame, text="Logged Networks", padding="10")
        log_display_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=5)
        
        # Log text widget
        self.log_text = tk.Text(log_display_frame, height=20, width=80,
                               bg='#1e1e1e', fg='#ffffff',
                               insertbackground='#ffffff',
                               selectbackground='#0078d4',
                               font=('Consolas', 9),
                               wrap=tk.WORD)
        
        log_scrollbar = ttk.Scrollbar(log_display_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Configure text tags
        self._configure_text_tags(self.log_text)
        
        # Configure weights
        self.log_frame.columnconfigure(0, weight=1)
        self.log_frame.rowconfigure(2, weight=1)
        log_display_frame.columnconfigure(0, weight=1)
        log_display_frame.rowconfigure(0, weight=1)
        
        # Load initial log (safely)
        try:
            self.refresh_network_log()
        except:
            self.log_text.insert(tk.END, "Network log will be available after first scan.")
    
    def log_current_network(self):
        """Log the currently analyzed network"""
        if not hasattr(self, 'current_network_for_log'):
            messagebox.showwarning("No Network", "No network analyzed. Please analyze a network first.")
            return
        
        network = self.current_network_for_log['network']
        analysis = self.current_network_for_log['analysis']
        
        if self.safe_scanner.log_threat(network, analysis):
            log_points = self.safe_scanner.add_log_points()
            messagebox.showinfo("Network Logged", f"Network '{network.get('ssid', 'Unknown')}' logged! +{log_points} points")
            self.refresh_network_log()
            self.refresh_score_display()
        else:
            messagebox.showinfo("Already Logged", "This network is already in the log or doesn't meet logging criteria.")
    
    def refresh_network_log(self):
        """Refresh the network log display"""
        try:
            log_content = self.safe_scanner.get_threat_summary()
            self.log_text.delete(1.0, tk.END)
            self.log_text.insert(tk.END, log_content)
        except Exception as e:
            self.log_text.delete(1.0, tk.END)
            self.log_text.insert(tk.END, f"Error loading log: {str(e)}")
    
    def clear_network_log(self):
        """Clear all network logs"""
        result = messagebox.askyesno("Clear Logs", "Are you sure you want to clear all network logs?")
        if result:
            try:
                self.safe_scanner.threats = []
                self.safe_scanner._save_threats()
                self.refresh_network_log()
                messagebox.showinfo("Logs Cleared", "All network logs have been cleared.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear logs: {str(e)}")
    
    def export_network_log(self):
        """Export network log to file"""
        try:
            if not self.safe_scanner.threats:
                messagebox.showinfo("No Data", "No networks logged to export.")
                return
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_log_export_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(self.safe_scanner.threats, f, indent=2)
            
            messagebox.showinfo("Export Complete", f"Network log exported to: {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export log: {str(e)}")
    
    def setup_score_tab(self):
        """Setup the security score tab"""
        # Header frame
        header_frame = ttk.LabelFrame(self.score_frame, text="Security Score & Achievements", padding="10")
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=10, pady=5)
        
        info_text = "Earn points by scanning networks and logging threats. Level up and unlock achievements!"
        ttk.Label(header_frame, text=info_text, wraplength=600).grid(row=0, column=0, sticky=tk.W)
        
        # Score display frame
        score_display_frame = ttk.LabelFrame(self.score_frame, text="Your Progress", padding="10")
        score_display_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=5)
        
        # Score text widget
        self.score_text = tk.Text(score_display_frame, height=15, width=60,
                                 bg='#1e1e1e', fg='#ffffff',
                                 insertbackground='#ffffff',
                                 selectbackground='#0078d4',
                                 font=('Consolas', 11),
                                 wrap=tk.WORD)
        
        score_scrollbar = ttk.Scrollbar(score_display_frame, orient=tk.VERTICAL, command=self.score_text.yview)
        self.score_text.configure(yscrollcommand=score_scrollbar.set)
        
        self.score_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        score_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Configure text tags for colors
        self.score_text.tag_configure('level', foreground='#ffaa00', font=('Consolas', 12, 'bold'))
        self.score_text.tag_configure('score', foreground='#44ff88', font=('Consolas', 11, 'bold'))
        self.score_text.tag_configure('achievement', foreground='#ffcc44', font=('Consolas', 10, 'bold'))
        self.score_text.tag_configure('stat', foreground='#88ccff')
        
        # Buttons frame
        buttons_frame = ttk.Frame(self.score_frame)
        buttons_frame.grid(row=2, column=0, pady=10)
        
        ttk.Button(buttons_frame, text="Refresh Score", 
                  command=self.refresh_score_display).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(buttons_frame, text="Reset Score", 
                  command=self.reset_score).grid(row=0, column=1)
        
        # Configure weights
        self.score_frame.columnconfigure(0, weight=1)
        self.score_frame.rowconfigure(1, weight=1)
        score_display_frame.columnconfigure(0, weight=1)
        score_display_frame.rowconfigure(0, weight=1)
        
        # Load initial score
        self.refresh_score_display()
    
    def refresh_score_display(self):
        """Refresh the security score display"""
        try:
            score_content = self.safe_scanner.get_score_summary()
            self.score_text.delete(1.0, tk.END)
            
            # Insert with color formatting
            lines = score_content.split('\n')
            for line in lines:
                if 'Level:' in line:
                    self.score_text.insert(tk.END, line + '\n', 'level')
                elif 'Total Score:' in line:
                    self.score_text.insert(tk.END, line + '\n', 'score')
                elif '🏆' in line:
                    self.score_text.insert(tk.END, line + '\n', 'achievement')
                elif '•' in line:
                    self.score_text.insert(tk.END, line + '\n', 'stat')
                else:
                    self.score_text.insert(tk.END, line + '\n')
        except Exception as e:
            self.score_text.delete(1.0, tk.END)
            self.score_text.insert(tk.END, f"Error loading score: {str(e)}")
    
    def reset_score(self):
        """Reset the security score"""
        result = messagebox.askyesno("Reset Score", "Are you sure you want to reset your security score and achievements?")
        if result:
            self.safe_scanner.user_score = {
                'total_score': 0,
                'networks_scanned': 0,
                'threats_logged': 0,
                'safe_networks_found': 0,
                'level': 1,
                'achievements': []
            }
            self.safe_scanner._save_score()
            self.refresh_score_display()
            messagebox.showinfo("Score Reset", "Your security score has been reset.")
    
    def log_simple_network(self):
        """Log network from simple scan"""
        if not hasattr(self, 'current_simple_analysis'):
            messagebox.showwarning("No Network", "No network analyzed. Please run a simple scan first.")
            return
        
        network = self.current_simple_analysis['network']
        analysis = self.current_simple_analysis['analysis']
        
        if self.safe_scanner.log_threat(network, analysis, 'simple_scan'):
            log_points = self.safe_scanner.add_log_points()
            messagebox.showinfo("Network Logged", f"Network '{network.get('ssid', 'Unknown')}' logged from Simple Scan! +{log_points} points")
            self.refresh_network_log()
            self.refresh_score_display()
        else:
            messagebox.showinfo("Already Logged", "This network is already logged from Simple Scan.")
    
    def log_advanced_network(self):
        """Log network from advanced scan"""
        if not hasattr(self, 'current_advanced_analysis'):
            messagebox.showwarning("No Network", "No network analyzed. Please run an advanced scan first.")
            return
        
        network = self.current_advanced_analysis['network']
        analysis = self.current_advanced_analysis['analysis']
        
        if self.safe_scanner.log_threat(network, analysis, 'advanced_scan'):
            log_points = self.safe_scanner.add_log_points()
            messagebox.showinfo("Network Logged", f"Network '{network.get('ssid', 'Unknown')}' logged from Advanced Scan! +{log_points} points")
            self.refresh_network_log()
            self.refresh_score_display()
        else:
            messagebox.showinfo("Already Logged", "This network is already logged from Advanced Scan.")

def main():
    """Main entry point for the application"""
    root = tk.Tk()
    app = WiFiSecurityTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()