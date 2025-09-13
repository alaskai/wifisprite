# UI Helper methods for WiFi Sprite main application

def _generate_advanced_report(self, network_info, analysis_results):
    """Generate advanced technical report"""
    return self.advanced_reporter.generate_advanced_report(network_info, analysis_results)

# Simple test UI update methods
def _update_simple_ui_safe(self, message):
    """Thread-safe simple UI update"""
    self.root.after(0, lambda: self._update_simple_ui(message))

def _update_simple_ui(self, message):
    """Update simple UI with message"""
    self.simple_results_text.delete(1.0, tk.END)
    self.simple_results_text.insert(tk.END, message)
    self.simple_progress.stop()
    self.simple_scan_button.config(state='normal')

def _update_simple_results_safe(self, network_info, analysis, report):
    """Thread-safe simple results update"""
    self.root.after(0, lambda: self._update_simple_results(network_info, analysis, report))

def _update_simple_results(self, network_info, analysis, report):
    """Update simple results display"""
    risk_level = analysis['overall_risk']
    risk_colors = {
        'HIGH': 'red',
        'MEDIUM': 'orange', 
        'LOW': 'yellow',
        'MINIMAL': 'green'
    }
    
    self.simple_risk_label.config(text=f"Security Status: {risk_level} RISK", 
                                 foreground=risk_colors.get(risk_level, 'black'))
    
    self.simple_results_text.delete(1.0, tk.END)
    self.simple_results_text.insert(tk.END, report)
    
    self.current_simple_analysis = {
        'network': network_info,
        'analysis': analysis,
        'report': report
    }

def _stop_simple_progress_safe(self):
    """Thread-safe simple progress stop"""
    self.root.after(0, self._stop_simple_progress)

def _stop_simple_progress(self):
    """Stop simple progress bar and re-enable button"""
    self.simple_progress.stop()
    self.simple_scan_button.config(state='normal')

# Advanced test UI update methods
def _update_advanced_ui_safe(self, message):
    """Thread-safe advanced UI update"""
    self.root.after(0, lambda: self._update_advanced_ui(message))

def _update_advanced_ui(self, message):
    """Update advanced UI with message"""
    self.advanced_results_text.delete(1.0, tk.END)
    self.advanced_results_text.insert(tk.END, message)
    self.advanced_progress.stop()
    self.advanced_scan_button.config(state='normal')
    self.status_label.config(text="Scan completed")

def _update_advanced_results_safe(self, network_info, analysis, report):
    """Thread-safe advanced results update"""
    self.root.after(0, lambda: self._update_advanced_results(network_info, analysis, report))

def _update_advanced_results(self, network_info, analysis, report):
    """Update advanced results display"""
    # Calculate overall risk from advanced analysis
    advanced_results = analysis.get('advanced', {})
    risk_level = analysis['overall_risk']
    
    # Upgrade risk level if honeypot detected
    if 'honeypot' in advanced_results and advanced_results['honeypot'].get('is_honeypot'):
        risk_level = 'CRITICAL'
    
    risk_colors = {
        'CRITICAL': 'red',
        'HIGH': 'red',
        'MEDIUM': 'orange', 
        'LOW': 'yellow',
        'MINIMAL': 'green'
    }
    
    self.advanced_risk_label.config(text=f"Security Status: {risk_level} RISK", 
                                   foreground=risk_colors.get(risk_level, 'black'))
    
    self.advanced_results_text.delete(1.0, tk.END)
    self.advanced_results_text.insert(tk.END, report)
    
    self.current_advanced_analysis = {
        'network': network_info,
        'analysis': analysis,
        'report': report
    }

def _stop_advanced_progress_safe(self):
    """Thread-safe advanced progress stop"""
    self.root.after(0, self._stop_advanced_progress)

def _stop_advanced_progress(self):
    """Stop advanced progress bar and re-enable button"""
    self.advanced_progress.stop()
    self.advanced_scan_button.config(state='normal')
    self.status_label.config(text="Ready to scan")

def _update_status_safe(self, message):
    """Thread-safe status update"""
    self.root.after(0, lambda: self.status_label.config(text=message))

def _update_current_network_safe(self, text):
    """Thread-safe current network label update"""
    self.root.after(0, lambda: self.current_network_label.config(text=text))

# Clear methods
def clear_simple_results(self):
    """Clear simple results display"""
    self.simple_results_text.delete(1.0, tk.END)
    self.simple_risk_label.config(text="Security Status: Unknown", foreground='black')
    if hasattr(self, 'current_simple_analysis'):
        del self.current_simple_analysis

def clear_advanced_results(self):
    """Clear advanced results display"""
    self.advanced_results_text.delete(1.0, tk.END)
    self.advanced_risk_label.config(text="Security Status: Unknown", foreground='black')
    self.status_label.config(text="Ready to scan")
    if hasattr(self, 'current_advanced_analysis'):
        del self.current_advanced_analysis

# Save report method
def save_report(self, report_type='simple'):
    """Save the current analysis report"""
    if report_type == 'simple':
        if not hasattr(self, 'current_simple_analysis'):
            messagebox.showwarning("No Report", "No simple analysis report to save. Please run a basic scan first.")
            return
        analysis_data = self.current_simple_analysis
        prefix = "basic"
    else:
        if not hasattr(self, 'current_advanced_analysis'):
            messagebox.showwarning("No Report", "No advanced analysis report to save. Please run an advanced scan first.")
            return
        analysis_data = self.current_advanced_analysis
        prefix = "advanced"
    
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"wifi_{prefix}_report_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(analysis_data['report'])
        
        # Also save JSON version
        json_filename = f"wifi_{prefix}_report_{timestamp}.json"
        json_report = self.reporter.generate_json_report(
            analysis_data['network'], 
            analysis_data['analysis']
        )
        
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(json_report, f, indent=2)
        
        messagebox.showinfo("Report Saved", 
                          f"Reports saved as:\n{filename}\n{json_filename}")
        
    except Exception as e:
        messagebox.showerror("Save Error", f"Failed to save report: {str(e)}")

def show_help(self):
    """Show help information"""
    help_text = """
WiFi Sprite - Advanced WiFi Security Analyzer

SIMPLE TEST:
• Basic encryption analysis
• Captive portal detection  
• Quick security assessment
• User-friendly results

ADVANCED TEST:
• Honeypot detection (detects fake access points)
• Network host discovery
• Traffic pattern analysis
• Comprehensive security assessment

HONEYPOT DETECTION:
Specifically designed for South African networks to detect:
• ESP32-based fake access points
• DNS hijacking attempts
• Fake internet connectivity
• Suspicious network timing

SECURITY RATINGS:
🔴 CRITICAL/HIGH - Disconnect immediately
🟠 MEDIUM - Use VPN, be cautious
🟡 LOW - Generally safe with precautions  
🟢 MINIMAL - Secure network

This tool is for educational and defensive security purposes only.
Use responsibly and in accordance with local laws.
    """
    messagebox.showinfo("Help - WiFi Sprite", help_text)