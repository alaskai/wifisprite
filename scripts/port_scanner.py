import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    def __init__(self):
        # Dictionary of potentially dangerous ports and their security implications
        self.dangerous_ports = {
            # Remote Access & Control
            21: {
                'service': 'FTP',
                'risk': 'HIGH',
                'description': 'File Transfer Protocol - often misconfigured, allows file access',
                'threats': ['Unauthorized file access', 'Data theft', 'Malware upload', 'Brute force attacks']
            },
            22: {
                'service': 'SSH',
                'risk': 'MEDIUM',
                'description': 'Secure Shell - remote command line access',
                'threats': ['Brute force attacks', 'Unauthorized system access', 'Lateral movement']
            },
            23: {
                'service': 'Telnet',
                'risk': 'CRITICAL',
                'description': 'Unencrypted remote access - sends passwords in plain text',
                'threats': ['Password interception', 'Complete system compromise', 'Man-in-the-middle attacks']
            },
            3389: {
                'service': 'RDP',
                'risk': 'HIGH',
                'description': 'Remote Desktop Protocol - Windows remote access',
                'threats': ['Brute force attacks', 'Ransomware deployment', 'System takeover']
            },
            5900: {
                'service': 'VNC',
                'risk': 'HIGH',
                'description': 'Virtual Network Computing - remote desktop access',
                'threats': ['Screen hijacking', 'Unauthorized control', 'Data theft']
            },
            
            # Web Services
            80: {
                'service': 'HTTP',
                'risk': 'MEDIUM',
                'description': 'Unencrypted web traffic',
                'threats': ['Data interception', 'Session hijacking', 'Malicious content injection']
            },
            443: {
                'service': 'HTTPS',
                'risk': 'LOW',
                'description': 'Encrypted web traffic (generally safe)',
                'threats': ['Certificate spoofing', 'SSL/TLS vulnerabilities']
            },
            8080: {
                'service': 'HTTP-Alt',
                'risk': 'MEDIUM',
                'description': 'Alternative HTTP port, often used by proxies',
                'threats': ['Proxy abuse', 'Unauthorized web access', 'Traffic interception']
            },
            8443: {
                'service': 'HTTPS-Alt',
                'risk': 'MEDIUM',
                'description': 'Alternative HTTPS port',
                'threats': ['Certificate spoofing', 'Fake SSL services']
            },
            
            # Database Services
            1433: {
                'service': 'MSSQL',
                'risk': 'CRITICAL',
                'description': 'Microsoft SQL Server database',
                'threats': ['Database compromise', 'Data theft', 'SQL injection', 'Privilege escalation']
            },
            3306: {
                'service': 'MySQL',
                'risk': 'CRITICAL',
                'description': 'MySQL database server',
                'threats': ['Database breach', 'Data extraction', 'Unauthorized queries']
            },
            5432: {
                'service': 'PostgreSQL',
                'risk': 'CRITICAL',
                'description': 'PostgreSQL database server',
                'threats': ['Database compromise', 'Data theft', 'Privilege escalation']
            },
            27017: {
                'service': 'MongoDB',
                'risk': 'CRITICAL',
                'description': 'MongoDB NoSQL database',
                'threats': ['Database exposure', 'Data theft', 'Ransomware attacks']
            },
            
            # File Sharing
            139: {
                'service': 'NetBIOS',
                'risk': 'HIGH',
                'description': 'Windows file sharing (legacy)',
                'threats': ['File system access', 'Network enumeration', 'Lateral movement']
            },
            445: {
                'service': 'SMB',
                'risk': 'HIGH',
                'description': 'Server Message Block - Windows file sharing',
                'threats': ['Ransomware spread', 'File access', 'EternalBlue exploits']
            },
            2049: {
                'service': 'NFS',
                'risk': 'HIGH',
                'description': 'Network File System - Unix/Linux file sharing',
                'threats': ['Unauthorized file access', 'Data theft', 'System compromise']
            },
            
            # Email Services
            25: {
                'service': 'SMTP',
                'risk': 'MEDIUM',
                'description': 'Simple Mail Transfer Protocol',
                'threats': ['Email relay abuse', 'Spam distribution', 'Phishing campaigns']
            },
            110: {
                'service': 'POP3',
                'risk': 'MEDIUM',
                'description': 'Post Office Protocol (unencrypted email)',
                'threats': ['Email interception', 'Credential theft', 'Privacy breach']
            },
            143: {
                'service': 'IMAP',
                'risk': 'MEDIUM',
                'description': 'Internet Message Access Protocol (unencrypted)',
                'threats': ['Email access', 'Credential theft', 'Privacy violation']
            },
            
            # Network Services
            53: {
                'service': 'DNS',
                'risk': 'MEDIUM',
                'description': 'Domain Name System',
                'threats': ['DNS poisoning', 'Traffic redirection', 'Data exfiltration']
            },
            161: {
                'service': 'SNMP',
                'risk': 'HIGH',
                'description': 'Simple Network Management Protocol',
                'threats': ['Network reconnaissance', 'Device control', 'Information disclosure']
            },
            
            # Backdoors & Trojans
            1234: {
                'service': 'Backdoor',
                'risk': 'CRITICAL',
                'description': 'Common backdoor/trojan port',
                'threats': ['System compromise', 'Remote control', 'Data theft']
            },
            4444: {
                'service': 'Backdoor',
                'risk': 'CRITICAL',
                'description': 'Common backdoor/trojan port',
                'threats': ['Remote access trojan', 'System control', 'Malware C&C']
            },
            6666: {
                'service': 'Backdoor',
                'risk': 'CRITICAL',
                'description': 'Common backdoor/trojan port',
                'threats': ['Trojan communication', 'System compromise', 'Data exfiltration']
            },
            31337: {
                'service': 'BackOrifice',
                'risk': 'CRITICAL',
                'description': 'BackOrifice trojan default port',
                'threats': ['Complete system control', 'Data theft', 'Remote surveillance']
            },
            
            # IoT & Embedded Devices
            8888: {
                'service': 'IoT/Web',
                'risk': 'HIGH',
                'description': 'Common IoT device web interface',
                'threats': ['Device hijacking', 'Botnet recruitment', 'Privacy invasion']
            },
            9999: {
                'service': 'IoT/Telnet',
                'risk': 'HIGH',
                'description': 'Common IoT device management',
                'threats': ['Device compromise', 'Botnet participation', 'Network infiltration']
            },
            
            # Development & Debug
            3000: {
                'service': 'Dev Server',
                'risk': 'MEDIUM',
                'description': 'Development web server (Node.js, etc.)',
                'threats': ['Code exposure', 'Debug access', 'Unintended functionality']
            },
            8000: {
                'service': 'Dev Server',
                'risk': 'MEDIUM',
                'description': 'Development/testing web server',
                'threats': ['Source code access', 'Debug information', 'Unprotected endpoints']
            },
            
            # Gaming & P2P
            6881: {
                'service': 'BitTorrent',
                'risk': 'MEDIUM',
                'description': 'BitTorrent peer-to-peer file sharing',
                'threats': ['Copyright infringement', 'Malware distribution', 'Bandwidth abuse']
            },
            
            # Proxy & Tunneling
            1080: {
                'service': 'SOCKS',
                'risk': 'HIGH',
                'description': 'SOCKS proxy server',
                'threats': ['Traffic tunneling', 'Anonymization abuse', 'Malicious proxy']
            },
            3128: {
                'service': 'Squid Proxy',
                'risk': 'MEDIUM',
                'description': 'HTTP proxy server',
                'threats': ['Traffic interception', 'Content filtering bypass', 'Privacy breach']
            }
        }
        
        # Common ports to scan (subset of dangerous ports + common services)
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
            1080, 1433, 3306, 3389, 5432, 5900, 8080, 8443, 8888
        ]
        
        # Extended scan includes more ports
        self.extended_ports = list(self.dangerous_ports.keys()) + [
            135, 993, 995, 1723, 5060, 5061, 6000, 7001, 8001, 8081, 9000, 9001
        ]
    
    def scan_network_ports(self, target_ip=None, scan_type='common', timeout=1):
        """Scan for open ports on network devices"""
        results = {
            'target': target_ip or 'Network Gateway',
            'scan_type': scan_type,
            'open_ports': [],
            'dangerous_ports': [],
            'security_issues': [],
            'recommendations': []
        }
        
        if not target_ip:
            target_ip = self._get_gateway_ip()
            
        if not target_ip:
            results['security_issues'].append('Could not determine target IP for port scanning')
            return results
            
        # Select ports to scan
        ports_to_scan = self.common_ports if scan_type == 'common' else self.extended_ports
        
        # Perform port scan
        open_ports = self._scan_ports(target_ip, ports_to_scan, timeout)
        results['open_ports'] = open_ports
        
        # Analyze dangerous ports
        dangerous_found = []
        for port in open_ports:
            if port in self.dangerous_ports:
                port_info = self.dangerous_ports[port].copy()
                port_info['port'] = port
                dangerous_found.append(port_info)
                
        results['dangerous_ports'] = dangerous_found
        
        # Generate security analysis
        results['security_issues'] = self._analyze_port_security(dangerous_found)
        results['recommendations'] = self._generate_port_recommendations(dangerous_found)
        
        return results
    
    def _scan_ports(self, target_ip, ports, timeout):
        """Scan specific ports on target IP"""
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                
                if result == 0:
                    return port
            except Exception:
                pass
            return None
        
        # Use threading for faster scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            
            for future in futures:
                try:
                    result = future.result(timeout=timeout + 1)
                    if result:
                        open_ports.append(result)
                except Exception:
                    pass
                    
        return sorted(open_ports)
    
    def _analyze_port_security(self, dangerous_ports):
        """Analyze security implications of open dangerous ports"""
        issues = []
        
        # Categorize by risk level
        critical_ports = [p for p in dangerous_ports if p['risk'] == 'CRITICAL']
        high_ports = [p for p in dangerous_ports if p['risk'] == 'HIGH']
        medium_ports = [p for p in dangerous_ports if p['risk'] == 'MEDIUM']
        
        if critical_ports:
            issues.append(f"🚨 CRITICAL: {len(critical_ports)} extremely dangerous ports open")
            for port in critical_ports:
                issues.append(f"   Port {port['port']} ({port['service']}): {port['description']}")
                
        if high_ports:
            issues.append(f"🔴 HIGH RISK: {len(high_ports)} high-risk ports open")
            for port in high_ports:
                issues.append(f"   Port {port['port']} ({port['service']}): {port['description']}")
                
        if medium_ports:
            issues.append(f"🟠 MEDIUM RISK: {len(medium_ports)} medium-risk ports open")
            
        # Specific threat analysis
        if any(p['port'] in [23, 21] for p in dangerous_ports):
            issues.append("⚠️ Unencrypted protocols detected - credentials at risk")
            
        if any(p['port'] in [1433, 3306, 5432, 27017] for p in dangerous_ports):
            issues.append("💾 Database services exposed - data breach risk")
            
        if any(p['port'] in [139, 445] for p in dangerous_ports):
            issues.append("📁 File sharing services exposed - ransomware risk")
            
        if any(p['port'] in [1234, 4444, 6666, 31337] for p in dangerous_ports):
            issues.append("🦠 Potential backdoor/trojan ports detected")
            
        return issues
    
    def _generate_port_recommendations(self, dangerous_ports):
        """Generate security recommendations based on open ports"""
        recommendations = []
        
        if not dangerous_ports:
            recommendations.append("✅ No dangerous ports detected in scan")
            recommendations.append("💡 Regular port scanning helps maintain security")
            return recommendations
            
        # General recommendations
        recommendations.append("🔒 IMMEDIATE ACTIONS REQUIRED:")
        
        # Critical ports
        critical_ports = [p for p in dangerous_ports if p['risk'] == 'CRITICAL']
        if critical_ports:
            recommendations.append("🚨 Disconnect from this network immediately")
            recommendations.append("🚨 Critical security vulnerabilities detected")
            
        # Specific recommendations by service type
        if any(p['port'] in [23, 21] for p in dangerous_ports):
            recommendations.append("🔐 Disable unencrypted protocols (Telnet, FTP)")
            recommendations.append("🔐 Use SSH/SFTP instead of Telnet/FTP")
            
        if any(p['port'] in [1433, 3306, 5432] for p in dangerous_ports):
            recommendations.append("💾 Secure database services immediately")
            recommendations.append("💾 Implement database firewalls and access controls")
            
        if any(p['port'] in [139, 445] for p in dangerous_ports):
            recommendations.append("📁 Disable unnecessary file sharing")
            recommendations.append("📁 Update Windows systems (EternalBlue protection)")
            
        if any(p['port'] in [3389, 5900] for p in dangerous_ports):
            recommendations.append("🖥️ Secure remote access services")
            recommendations.append("🖥️ Use VPN for remote access instead")
            
        # General security recommendations
        recommendations.extend([
            "🛡️ Enable firewall on all devices",
            "🔄 Keep all software and firmware updated",
            "🔍 Perform regular security audits",
            "📊 Monitor network traffic for suspicious activity",
            "🚫 Close unnecessary ports and services",
            "🔐 Use strong authentication for all services"
        ])
        
        return recommendations
    
    def _get_gateway_ip(self):
        """Get the default gateway IP address"""
        try:
            import subprocess
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'Default Gateway' in line:
                    gateway = line.split(':')[-1].strip()
                    if gateway and gateway != '':
                        return gateway
        except Exception:
            pass
        return None
    
    def get_port_info(self, port):
        """Get detailed information about a specific port"""
        if port in self.dangerous_ports:
            return self.dangerous_ports[port]
        else:
            return {
                'service': 'Unknown',
                'risk': 'LOW',
                'description': 'Port not in dangerous ports database',
                'threats': ['Unknown service - investigate manually']
            }
    
    def generate_port_report(self, scan_results):
        """Generate a detailed port scan report"""
        report = []
        
        report.append("=" * 50)
        report.append("NETWORK PORT SECURITY ANALYSIS")
        report.append("=" * 50)
        report.append(f"Target: {scan_results['target']}")
        report.append(f"Scan Type: {scan_results['scan_type'].upper()}")
        report.append(f"Open Ports Found: {len(scan_results['open_ports'])}")
        report.append(f"Dangerous Ports: {len(scan_results['dangerous_ports'])}")
        report.append("")
        
        # Open ports summary
        if scan_results['open_ports']:
            report.append("OPEN PORTS DETECTED:")
            report.append("-" * 20)
            for port in scan_results['open_ports']:
                if port in self.dangerous_ports:
                    info = self.dangerous_ports[port]
                    risk_indicator = "🚨" if info['risk'] == 'CRITICAL' else "🔴" if info['risk'] == 'HIGH' else "🟠"
                    report.append(f"  {risk_indicator} Port {port}: {info['service']} ({info['risk']} RISK)")
                else:
                    report.append(f"  ℹ️ Port {port}: Unknown service")
            report.append("")
        
        # Dangerous ports details
        if scan_results['dangerous_ports']:
            report.append("DANGEROUS PORTS ANALYSIS:")
            report.append("-" * 28)
            for port_info in scan_results['dangerous_ports']:
                port = port_info['port']
                report.append(f"Port {port} - {port_info['service']} ({port_info['risk']} RISK)")
                report.append(f"  Description: {port_info['description']}")
                report.append(f"  Potential Threats:")
                for threat in port_info['threats']:
                    report.append(f"    • {threat}")
                report.append("")
        
        # Security issues
        if scan_results['security_issues']:
            report.append("SECURITY ISSUES IDENTIFIED:")
            report.append("-" * 30)
            for issue in scan_results['security_issues']:
                report.append(f"  {issue}")
            report.append("")
        
        # Recommendations
        if scan_results['recommendations']:
            report.append("SECURITY RECOMMENDATIONS:")
            report.append("-" * 28)
            for rec in scan_results['recommendations']:
                report.append(f"  {rec}")
            report.append("")
        
        report.append("Port scan completed - WiFi Sprite Security Analyzer")
        
        return "\n".join(report)