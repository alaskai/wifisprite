import time
import threading
from collections import defaultdict, Counter
from scapy.all import *
import statistics

class TrafficAnalyzer:
    def __init__(self):
        self.packets_captured = []
        self.analysis_results = {}
        self.monitoring = False
        
    def analyze_traffic(self, duration=30, analysis_type='discrete'):
        """Analyze network traffic for suspicious patterns"""
        results = {
            'analysis_type': analysis_type,
            'duration': duration,
            'packets_analyzed': 0,
            'suspicious_patterns': [],
            'traffic_summary': {},
            'security_issues': []
        }
        
        # Start packet capture
        self.packets_captured = []
        self.monitoring = True
        
        if analysis_type == 'discrete':
            results = self._passive_traffic_analysis(duration)
        elif analysis_type == 'comprehensive':
            results = self._active_traffic_analysis(duration)
            
        return results
    
    def _passive_traffic_analysis(self, duration):
        """Passive traffic monitoring and analysis"""
        results = {
            'packets_analyzed': 0,
            'suspicious_patterns': [],
            'traffic_summary': {},
            'security_issues': [],
            'protocol_distribution': {},
            'top_talkers': {},
            'anomalies': []
        }
        
        # Capture packets
        def packet_handler(packet):
            if self.monitoring:
                self.packets_captured.append({
                    'timestamp': time.time(),
                    'packet': packet,
                    'size': len(packet)
                })
        
        try:
            print(f"Monitoring traffic for {duration} seconds...")
            sniff(prn=packet_handler, timeout=duration, store=0)
        except Exception as e:
            results['security_issues'].append(f"Traffic capture error: {str(e)}")
            
        self.monitoring = False
        results['packets_analyzed'] = len(self.packets_captured)
        
        if self.packets_captured:
            # Analyze captured packets
            results.update(self._analyze_captured_packets())
            
        return results
    
    def _active_traffic_analysis(self, duration):
        """Active traffic analysis with additional probing"""
        # Start with passive analysis
        results = self._passive_traffic_analysis(duration)
        
        # Add active probing results
        active_results = self._perform_active_probes()
        results['active_probes'] = active_results
        
        return results
    
    def _analyze_captured_packets(self):
        """Analyze captured packets for suspicious patterns"""
        analysis = {
            'protocol_distribution': defaultdict(int),
            'top_talkers': defaultdict(int),
            'suspicious_patterns': [],
            'security_issues': [],
            'anomalies': [],
            'traffic_summary': {}
        }
        
        # Protocol analysis
        for packet_info in self.packets_captured:
            packet = packet_info['packet']
            
            if packet.haslayer(IP):
                # Protocol distribution
                if packet.haslayer(TCP):
                    analysis['protocol_distribution']['TCP'] += 1
                elif packet.haslayer(UDP):
                    analysis['protocol_distribution']['UDP'] += 1
                elif packet.haslayer(ICMP):
                    analysis['protocol_distribution']['ICMP'] += 1
                    
                # Top talkers
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                analysis['top_talkers'][src_ip] += 1
                analysis['top_talkers'][dst_ip] += 1
                
        # Detect suspicious patterns
        analysis['suspicious_patterns'].extend(self._detect_suspicious_patterns())
        analysis['security_issues'].extend(self._detect_security_issues())
        analysis['anomalies'].extend(self._detect_anomalies())
        
        # Generate traffic summary
        analysis['traffic_summary'] = self._generate_traffic_summary()
        
        return analysis
    
    def _detect_suspicious_patterns(self):
        """Detect suspicious traffic patterns"""
        patterns = []
        
        # Pattern 1: Excessive DNS queries
        dns_count = 0
        for packet_info in self.packets_captured:
            packet = packet_info['packet']
            if packet.haslayer(DNS):
                dns_count += 1
                
        if dns_count > len(self.packets_captured) * 0.3:
            patterns.append({
                'type': 'Excessive DNS Queries',
                'description': f'{dns_count} DNS queries detected - possible DNS tunneling',
                'severity': 'Medium'
            })
            
        # Pattern 2: Port scanning detection
        port_scan_ips = self._detect_port_scanning()
        for ip in port_scan_ips:
            patterns.append({
                'type': 'Port Scanning',
                'description': f'Port scanning detected from {ip}',
                'severity': 'High'
            })
            
        # Pattern 3: Unusual protocol usage
        unusual_protocols = self._detect_unusual_protocols()
        for protocol in unusual_protocols:
            patterns.append({
                'type': 'Unusual Protocol',
                'description': f'Unusual protocol usage: {protocol}',
                'severity': 'Low'
            })
            
        # Pattern 4: Data exfiltration indicators
        exfiltration_indicators = self._detect_data_exfiltration()
        patterns.extend(exfiltration_indicators)
        
        return patterns
    
    def _detect_security_issues(self):
        """Detect security-related issues in traffic"""
        issues = []
        
        # Issue 1: Unencrypted credentials
        credential_packets = self._find_credential_packets()
        if credential_packets:
            issues.append({
                'type': 'Unencrypted Credentials',
                'description': f'{len(credential_packets)} packets with potential credentials detected',
                'severity': 'Critical'
            })
            
        # Issue 2: Suspicious HTTP requests
        suspicious_http = self._analyze_http_traffic()
        issues.extend(suspicious_http)
        
        # Issue 3: Certificate issues
        cert_issues = self._analyze_ssl_certificates()
        issues.extend(cert_issues)
        
        return issues
    
    def _detect_anomalies(self):
        """Detect traffic anomalies"""
        anomalies = []
        
        if not self.packets_captured:
            return anomalies
            
        # Anomaly 1: Unusual packet sizes
        packet_sizes = [p['size'] for p in self.packets_captured]
        if packet_sizes:
            avg_size = statistics.mean(packet_sizes)
            large_packets = [s for s in packet_sizes if s > avg_size * 3]
            
            if len(large_packets) > len(packet_sizes) * 0.1:
                anomalies.append({
                    'type': 'Unusual Packet Sizes',
                    'description': f'{len(large_packets)} unusually large packets detected',
                    'severity': 'Low'
                })
                
        # Anomaly 2: Traffic timing patterns
        timing_anomalies = self._analyze_timing_patterns()
        anomalies.extend(timing_anomalies)
        
        return anomalies
    
    def _detect_port_scanning(self):
        """Detect port scanning activity"""
        port_attempts = defaultdict(set)
        
        for packet_info in self.packets_captured:
            packet = packet_info['packet']
            if packet.haslayer(TCP) and packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_port = packet[TCP].dport
                port_attempts[src_ip].add(dst_port)
                
        # IPs attempting to connect to many ports
        scanning_ips = []
        for ip, ports in port_attempts.items():
            if len(ports) > 10:  # Threshold for port scanning
                scanning_ips.append(ip)
                
        return scanning_ips
    
    def _detect_unusual_protocols(self):
        """Detect unusual protocol usage"""
        protocol_counts = defaultdict(int)
        
        for packet_info in self.packets_captured:
            packet = packet_info['packet']
            if packet.haslayer(IP):
                protocol = packet[IP].proto
                protocol_counts[protocol] += 1
                
        # Common protocols: TCP(6), UDP(17), ICMP(1)
        common_protocols = {1, 6, 17}
        unusual = []
        
        for protocol, count in protocol_counts.items():
            if protocol not in common_protocols and count > 5:
                unusual.append(f"Protocol {protocol} ({count} packets)")
                
        return unusual
    
    def _detect_data_exfiltration(self):
        """Detect potential data exfiltration patterns"""
        indicators = []
        
        # Large outbound transfers
        outbound_data = defaultdict(int)
        
        for packet_info in self.packets_captured:
            packet = packet_info['packet']
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                if self._is_local_ip(src_ip):
                    outbound_data[src_ip] += len(packet)
                    
        for ip, data_size in outbound_data.items():
            if data_size > 1024 * 1024:  # 1MB threshold
                indicators.append({
                    'type': 'Large Outbound Transfer',
                    'description': f'Large data transfer from {ip}: {data_size/1024/1024:.1f}MB',
                    'severity': 'Medium'
                })
                
        return indicators
    
    def _find_credential_packets(self):
        """Find packets that might contain credentials"""
        credential_packets = []
        credential_keywords = [b'password', b'passwd', b'login', b'username', b'user']
        
        for packet_info in self.packets_captured:
            packet = packet_info['packet']
            if packet.haslayer(Raw):
                payload = packet[Raw].load.lower()
                for keyword in credential_keywords:
                    if keyword in payload:
                        credential_packets.append(packet_info)
                        break
                        
        return credential_packets
    
    def _analyze_http_traffic(self):
        """Analyze HTTP traffic for suspicious patterns"""
        issues = []
        
        for packet_info in self.packets_captured:
            packet = packet_info['packet']
            if packet.haslayer(HTTP):
                # Check for suspicious HTTP requests
                if packet.haslayer(HTTPRequest):
                    method = packet[HTTPRequest].Method.decode()
                    path = packet[HTTPRequest].Path.decode()
                    
                    # Suspicious paths
                    suspicious_paths = ['/admin', '/login', '/wp-admin', '/.env', '/config']
                    for sus_path in suspicious_paths:
                        if sus_path in path:
                            issues.append({
                                'type': 'Suspicious HTTP Request',
                                'description': f'Suspicious path accessed: {path}',
                                'severity': 'Medium'
                            })
                            
        return issues
    
    def _analyze_ssl_certificates(self):
        """Analyze SSL/TLS certificates"""
        issues = []
        
        # This would require more complex SSL analysis
        # For now, just check for non-standard SSL ports
        ssl_ports = set()
        
        for packet_info in self.packets_captured:
            packet = packet_info['packet']
            if packet.haslayer(TCP) and packet.haslayer(IP):
                dst_port = packet[TCP].dport
                if dst_port == 443:  # HTTPS
                    ssl_ports.add(dst_port)
                elif dst_port in [8443, 9443, 8080]:  # Non-standard SSL ports
                    issues.append({
                        'type': 'Non-standard SSL Port',
                        'description': f'SSL traffic on non-standard port {dst_port}',
                        'severity': 'Low'
                    })
                    
        return issues
    
    def _analyze_timing_patterns(self):
        """Analyze timing patterns in traffic"""
        anomalies = []
        
        if len(self.packets_captured) < 10:
            return anomalies
            
        timestamps = [p['timestamp'] for p in self.packets_captured]
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if intervals:
            # Check for very regular intervals (possible automated traffic)
            interval_counts = Counter([round(interval, 1) for interval in intervals])
            most_common_interval, count = interval_counts.most_common(1)[0]
            
            if count > len(intervals) * 0.5:
                anomalies.append({
                    'type': 'Regular Traffic Pattern',
                    'description': f'Very regular traffic intervals detected ({most_common_interval}s)',
                    'severity': 'Low'
                })
                
        return anomalies
    
    def _generate_traffic_summary(self):
        """Generate summary of traffic analysis"""
        summary = {
            'total_packets': len(self.packets_captured),
            'duration': 0,
            'avg_packet_size': 0,
            'protocols': {},
            'top_sources': {},
            'top_destinations': {}
        }
        
        if not self.packets_captured:
            return summary
            
        # Calculate duration
        timestamps = [p['timestamp'] for p in self.packets_captured]
        summary['duration'] = max(timestamps) - min(timestamps)
        
        # Average packet size
        packet_sizes = [p['size'] for p in self.packets_captured]
        summary['avg_packet_size'] = statistics.mean(packet_sizes)
        
        # Protocol distribution
        protocol_counts = defaultdict(int)
        src_counts = defaultdict(int)
        dst_counts = defaultdict(int)
        
        for packet_info in self.packets_captured:
            packet = packet_info['packet']
            if packet.haslayer(IP):
                if packet.haslayer(TCP):
                    protocol_counts['TCP'] += 1
                elif packet.haslayer(UDP):
                    protocol_counts['UDP'] += 1
                elif packet.haslayer(ICMP):
                    protocol_counts['ICMP'] += 1
                    
                src_counts[packet[IP].src] += 1
                dst_counts[packet[IP].dst] += 1
                
        summary['protocols'] = dict(protocol_counts)
        summary['top_sources'] = dict(Counter(src_counts).most_common(5))
        summary['top_destinations'] = dict(Counter(dst_counts).most_common(5))
        
        return summary
    
    def _perform_active_probes(self):
        """Perform active network probes"""
        probes = {
            'dns_probes': self._probe_dns_servers(),
            'gateway_probes': self._probe_gateway(),
            'service_probes': self._probe_common_services()
        }
        
        return probes
    
    def _probe_dns_servers(self):
        """Probe DNS servers for suspicious responses"""
        results = []
        
        # Test queries to detect DNS manipulation
        test_queries = [
            'google.com',
            'facebook.com', 
            'nonexistent-domain-12345.com'
        ]
        
        for query in test_queries:
            try:
                response = sr1(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=query)), 
                             timeout=2, verbose=0)
                if response:
                    results.append({
                        'query': query,
                        'response': 'Received',
                        'suspicious': query == 'nonexistent-domain-12345.com'
                    })
            except:
                pass
                
        return results
    
    def _probe_gateway(self):
        """Probe gateway for additional information"""
        results = {}
        
        try:
            # Get gateway IP
            gateway_ip = self._get_gateway_ip()
            if gateway_ip:
                # Test HTTP response
                try:
                    response = sr1(IP(dst=gateway_ip)/TCP(dport=80, flags="S"), 
                                 timeout=2, verbose=0)
                    results['http_port'] = 'Open' if response else 'Closed'
                except:
                    results['http_port'] = 'Unknown'
                    
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def _probe_common_services(self):
        """Probe for common services on the network"""
        services = {}
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        
        # Test against gateway
        gateway_ip = self._get_gateway_ip()
        if gateway_ip:
            for port in common_ports:
                try:
                    response = sr1(IP(dst=gateway_ip)/TCP(dport=port, flags="S"), 
                                 timeout=1, verbose=0)
                    services[port] = 'Open' if response and response.haslayer(TCP) and response[TCP].flags == 18 else 'Closed'
                except:
                    services[port] = 'Unknown'
                    
        return services
    
    def _is_local_ip(self, ip):
        """Check if IP is in local network"""
        try:
            import ipaddress
            ip_obj = ipaddress.IPv4Address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def _get_gateway_ip(self):
        """Get gateway IP address"""
        try:
            import subprocess
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'Default Gateway' in line:
                    gateway = line.split(':')[-1].strip()
                    if gateway and gateway != '':
                        return gateway
        except:
            pass
        return None