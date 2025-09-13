from datetime import datetime

class AdvancedReportGenerator:
    def __init__(self):
        pass
    
    def generate_advanced_report(self, network_info, analysis_results):
        """Generate comprehensive advanced security report"""
        report = []
        
        # Header
        report.append("=" * 60)
        report.append("ADVANCED WIFI SECURITY ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"Network: {network_info.get('ssid', 'Unknown')}")
        report.append(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"BSSID: {network_info.get('bssid', 'Unknown')}")
        report.append("")
        
        # Overall Risk Assessment
        overall_risk = self._calculate_overall_risk(analysis_results)
        risk_color = self._get_risk_indicator(overall_risk)
        
        report.append("OVERALL SECURITY ASSESSMENT")
        report.append("-" * 30)
        report.append(f"{risk_color} RISK LEVEL: {overall_risk}")
        report.append(f"Risk Score: {analysis_results.get('risk_score', 0)}/100")
        report.append("")
        
        # Basic Security Analysis
        report.append("BASIC SECURITY ANALYSIS")
        report.append("-" * 25)
        encryption = analysis_results.get('encryption', {})
        report.append(f"Encryption: {encryption.get('type', 'Unknown')}")
        report.append(f"Security Strength: {encryption.get('strength', 'Unknown')}")
        report.append("")
        
        # Advanced Test Results
        advanced = analysis_results.get('advanced', {})
        
        # Honeypot Detection Results
        if 'honeypot' in advanced:
            report.extend(self._format_honeypot_results(advanced['honeypot']))
            
        # Host Scanning Results
        if 'hosts' in advanced:
            report.extend(self._format_host_results(advanced['hosts']))
            
        # Traffic Analysis Results
        if 'traffic' in advanced:
            report.extend(self._format_traffic_results(advanced['traffic']))
            
        # Security Recommendations
        report.extend(self._generate_security_recommendations(analysis_results))
        
        # Technical Details
        report.extend(self._generate_technical_details(network_info, analysis_results))
        
        return "\n".join(report)
    
    def _calculate_overall_risk(self, analysis_results):
        """Calculate overall risk level from all analysis results"""
        risk_score = 0
        
        # Basic security risk
        basic_risk = analysis_results.get('overall_risk', 'LOW')
        risk_mapping = {'MINIMAL': 10, 'LOW': 25, 'MEDIUM': 50, 'HIGH': 75, 'CRITICAL': 90}
        risk_score += risk_mapping.get(basic_risk, 25)
        
        # Advanced test risks
        advanced = analysis_results.get('advanced', {})
        
        # Honeypot detection
        if 'honeypot' in advanced:
            honeypot = advanced['honeypot']
            if honeypot.get('is_honeypot', False):
                risk_score += honeypot.get('confidence', 0)
                
        # Host scanning risks
        if 'hosts' in advanced:
            hosts = advanced['hosts']
            suspicious_hosts = len([h for h in hosts.get('hosts_found', []) 
                                  if 'suspicious' in str(h).lower()])
            risk_score += min(suspicious_hosts * 10, 30)
            
        # Traffic analysis risks
        if 'traffic' in advanced:
            traffic = advanced['traffic']
            suspicious_patterns = len(traffic.get('suspicious_patterns', []))
            security_issues = len(traffic.get('security_issues', []))
            risk_score += min((suspicious_patterns + security_issues) * 5, 25)
            
        # Cap at 100
        risk_score = min(risk_score, 100)
        
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 40:
            return 'MEDIUM'
        elif risk_score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _get_risk_indicator(self, risk_level):
        """Get visual risk indicator"""
        indicators = {
            'CRITICAL': '🔴 CRITICAL',
            'HIGH': '🟠 HIGH',
            'MEDIUM': '🟡 MEDIUM', 
            'LOW': '🟢 LOW',
            'MINIMAL': '🟢 MINIMAL'
        }
        return indicators.get(risk_level, '⚪ UNKNOWN')
    
    def _format_honeypot_results(self, honeypot_results):
        """Format honeypot detection results"""
        report = []
        report.append("HONEYPOT DETECTION ANALYSIS")
        report.append("-" * 30)
        
        is_honeypot = honeypot_results.get('is_honeypot', False)
        confidence = honeypot_results.get('confidence', 0)
        
        if is_honeypot:
            report.append(f"🚨 POTENTIAL HONEYPOT DETECTED (Confidence: {confidence}%)")
            report.append("")
            report.append("Suspicious Indicators:")
            for indicator in honeypot_results.get('indicators', []):
                report.append(f"  • {indicator}")
        else:
            report.append("✅ No honeypot indicators detected")
            
        report.append("")
        report.append("Tests Performed:")
        for test in honeypot_results.get('tests_performed', []):
            report.append(f"  • {test}")
            
        report.append("")
        return report
    
    def _format_host_results(self, host_results):
        """Format host scanning results"""
        report = []
        report.append("NETWORK HOST ANALYSIS")
        report.append("-" * 25)
        
        hosts_found = host_results.get('hosts_found', [])
        report.append(f"Active Hosts Discovered: {len(hosts_found)}")
        report.append(f"Scan Method: {host_results.get('scan_method', 'Unknown')}")
        report.append(f"Network Range: {host_results.get('network_range', 'Unknown')}")
        report.append("")
        
        if hosts_found:
            report.append("Discovered Hosts:")
            for i, host in enumerate(hosts_found[:10], 1):  # Limit to first 10
                ip = host.get('ip', 'Unknown')
                hostname = host.get('hostname', 'Unknown')
                os_guess = host.get('os_guess', 'Unknown')
                services = host.get('services', {})
                
                report.append(f"  {i}. {ip}")
                if hostname != 'Unknown':
                    report.append(f"     Hostname: {hostname}")
                if os_guess != 'Unknown':
                    report.append(f"     OS: {os_guess}")
                if services:
                    report.append(f"     Services: {len(services)} detected")
                    
            if len(hosts_found) > 10:
                report.append(f"  ... and {len(hosts_found) - 10} more hosts")
        else:
            report.append("No additional hosts discovered")
            
        report.append("")
        return report
    
    def _format_traffic_results(self, traffic_results):
        """Format traffic analysis results"""
        report = []
        report.append("NETWORK TRAFFIC ANALYSIS")
        report.append("-" * 28)
        
        packets_analyzed = traffic_results.get('packets_analyzed', 0)
        report.append(f"Packets Analyzed: {packets_analyzed}")
        
        if packets_analyzed > 0:
            # Suspicious patterns
            suspicious_patterns = traffic_results.get('suspicious_patterns', [])
            if suspicious_patterns:
                report.append("")
                report.append("🚨 Suspicious Traffic Patterns:")
                for pattern in suspicious_patterns:
                    severity = pattern.get('severity', 'Unknown')
                    pattern_type = pattern.get('type', 'Unknown')
                    description = pattern.get('description', 'No description')
                    report.append(f"  • [{severity}] {pattern_type}: {description}")
                    
            # Security issues
            security_issues = traffic_results.get('security_issues', [])
            if security_issues:
                report.append("")
                report.append("🔒 Security Issues Detected:")
                for issue in security_issues:
                    severity = issue.get('severity', 'Unknown')
                    issue_type = issue.get('type', 'Unknown')
                    description = issue.get('description', 'No description')
                    report.append(f"  • [{severity}] {issue_type}: {description}")
                    
            # Traffic summary
            summary = traffic_results.get('traffic_summary', {})
            if summary:
                report.append("")
                report.append("Traffic Summary:")
                report.append(f"  • Duration: {summary.get('duration', 0):.1f} seconds")
                report.append(f"  • Average Packet Size: {summary.get('avg_packet_size', 0):.0f} bytes")
                
                protocols = summary.get('protocols', {})
                if protocols:
                    report.append("  • Protocol Distribution:")
                    for protocol, count in protocols.items():
                        report.append(f"    - {protocol}: {count} packets")
        else:
            report.append("No traffic captured for analysis")
            
        report.append("")
        return report
    
    def _generate_security_recommendations(self, analysis_results):
        """Generate security recommendations based on analysis"""
        report = []
        report.append("SECURITY RECOMMENDATIONS")
        report.append("-" * 28)
        
        recommendations = []
        
        # Basic security recommendations
        encryption = analysis_results.get('encryption', {})
        if encryption.get('type') in ['NONE', 'WEP']:
            recommendations.append("🔴 CRITICAL: Avoid this network - no encryption or weak WEP encryption")
            recommendations.append("🔴 Use mobile data or find a WPA2/WPA3 secured network")
            
        # Honeypot recommendations
        advanced = analysis_results.get('advanced', {})
        if 'honeypot' in advanced and advanced['honeypot'].get('is_honeypot'):
            recommendations.append("🚨 CRITICAL: Potential honeypot detected - disconnect immediately")
            recommendations.append("🚨 Do not enter any personal information or credentials")
            recommendations.append("🚨 Report this network to local authorities if suspicious")
            
        # Host scanning recommendations
        if 'hosts' in advanced:
            hosts_count = len(advanced['hosts'].get('hosts_found', []))
            if hosts_count > 20:
                recommendations.append("⚠️ Large number of network devices detected")
                recommendations.append("⚠️ Use VPN and avoid sensitive activities")
                
        # Traffic analysis recommendations
        if 'traffic' in advanced:
            traffic = advanced['traffic']
            if traffic.get('suspicious_patterns') or traffic.get('security_issues'):
                recommendations.append("🔒 Suspicious network activity detected")
                recommendations.append("🔒 Enable VPN and monitor your connections")
                
        # General recommendations
        recommendations.extend([
            "💡 Always use HTTPS websites when possible",
            "💡 Enable two-factor authentication on important accounts",
            "💡 Keep your device's security software updated",
            "💡 Avoid accessing banking or sensitive sites on public WiFi"
        ])
        
        for rec in recommendations:
            report.append(f"  {rec}")
            
        report.append("")
        return report
    
    def _generate_technical_details(self, network_info, analysis_results):
        """Generate technical details section"""
        report = []
        report.append("TECHNICAL DETAILS")
        report.append("-" * 18)
        
        # Network information
        report.append("Network Information:")
        report.append(f"  • SSID: {network_info.get('ssid', 'Unknown')}")
        report.append(f"  • BSSID: {network_info.get('bssid', 'Unknown')}")
        report.append(f"  • Channel: {network_info.get('channel', 'Unknown')}")
        report.append(f"  • Signal Strength: {network_info.get('signal_strength', 'Unknown')}")
        report.append(f"  • Frequency: {network_info.get('frequency', 'Unknown')}")
        
        # Security details
        encryption = analysis_results.get('encryption', {})
        if encryption:
            report.append("")
            report.append("Security Details:")
            report.append(f"  • Encryption Type: {encryption.get('type', 'Unknown')}")
            report.append(f"  • Authentication: {encryption.get('authentication', 'Unknown')}")
            report.append(f"  • Cipher: {encryption.get('cipher', 'Unknown')}")
            
        # Advanced test details
        advanced = analysis_results.get('advanced', {})
        if advanced:
            report.append("")
            report.append("Advanced Test Summary:")
            
            if 'honeypot' in advanced:
                honeypot = advanced['honeypot']
                report.append(f"  • Honeypot Detection: {len(honeypot.get('tests_performed', []))} tests")
                
            if 'hosts' in advanced:
                hosts = advanced['hosts']
                report.append(f"  • Host Discovery: {len(hosts.get('hosts_found', []))} hosts found")
                
            if 'traffic' in advanced:
                traffic = advanced['traffic']
                report.append(f"  • Traffic Analysis: {traffic.get('packets_analyzed', 0)} packets")
                
        report.append("")
        report.append("Report generated by WiFi Sprite - Advanced Security Analyzer")
        report.append(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        return report