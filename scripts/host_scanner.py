import socket
import threading
import subprocess
import time
from scapy.all import *
import ipaddress

class HostScanner:
    def __init__(self):
        self.discovered_hosts = []
        self.scan_results = {}
        
    def scan_network(self, network_range=None, scan_type='discrete'):
        """Scan network for active hosts"""
        if not network_range:
            network_range = self._get_network_range()
            
        results = {
            'hosts_found': [],
            'scan_method': scan_type,
            'network_range': network_range,
            'scan_time': time.time()
        }
        
        if scan_type == 'discrete':
            results['hosts_found'] = self._passive_host_discovery(network_range)
        elif scan_type == 'comprehensive':
            results['hosts_found'] = self._active_host_discovery(network_range)
            
        # Perform service detection on discovered hosts
        for host in results['hosts_found']:
            host['services'] = self._detect_services(host['ip'])
            host['os_guess'] = self._guess_os(host)
            
        return results
    
    def _get_network_range(self):
        """Get the current network range"""
        try:
            # Get local IP and subnet
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Assume /24 subnet (most common)
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            return str(network)
            
        except Exception as e:
            return "192.168.1.0/24"  # Default fallback
    
    def _passive_host_discovery(self, network_range):
        """Passive host discovery using ARP table and traffic monitoring"""
        hosts = []
        
        # Method 1: Parse ARP table
        arp_hosts = self._parse_arp_table()
        hosts.extend(arp_hosts)
        
        # Method 2: Monitor network traffic briefly
        traffic_hosts = self._monitor_traffic(duration=10)
        hosts.extend(traffic_hosts)
        
        # Remove duplicates
        unique_hosts = {}
        for host in hosts:
            if host['ip'] not in unique_hosts:
                unique_hosts[host['ip']] = host
                
        return list(unique_hosts.values())
    
    def _active_host_discovery(self, network_range):
        """Active host discovery using ping and port scanning"""
        hosts = []
        network = ipaddress.IPv4Network(network_range)
        
        # Ping sweep
        ping_hosts = self._ping_sweep(network)
        hosts.extend(ping_hosts)
        
        # TCP SYN scan on common ports
        syn_hosts = self._syn_scan(network)
        hosts.extend(syn_hosts)
        
        # Remove duplicates
        unique_hosts = {}
        for host in hosts:
            if host['ip'] not in unique_hosts:
                unique_hosts[host['ip']] = host
            else:
                # Merge information
                unique_hosts[host['ip']].update(host)
                
        return list(unique_hosts.values())
    
    def _parse_arp_table(self):
        """Parse system ARP table for discovered hosts"""
        hosts = []
        
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if '(' in line and ')' in line:
                    # Extract IP and MAC
                    ip_match = re.search(r'\(([\d.]+)\)', line)
                    mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                    
                    if ip_match and mac_match:
                        ip = ip_match.group(1)
                        mac = mac_match.group(0)
                        
                        hosts.append({
                            'ip': ip,
                            'mac': mac,
                            'discovery_method': 'ARP Table',
                            'hostname': self._resolve_hostname(ip)
                        })
                        
        except Exception as e:
            pass
            
        return hosts
    
    def _monitor_traffic(self, duration=10):
        """Monitor network traffic to discover active hosts"""
        hosts = {}
        
        def packet_handler(packet):
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Add source IP
                if self._is_local_ip(src_ip):
                    hosts[src_ip] = {
                        'ip': src_ip,
                        'discovery_method': 'Traffic Monitoring',
                        'hostname': self._resolve_hostname(src_ip),
                        'last_seen': time.time()
                    }
                    
                # Add destination IP if local
                if self._is_local_ip(dst_ip):
                    hosts[dst_ip] = {
                        'ip': dst_ip,
                        'discovery_method': 'Traffic Monitoring', 
                        'hostname': self._resolve_hostname(dst_ip),
                        'last_seen': time.time()
                    }
        
        try:
            # Sniff packets for specified duration
            sniff(prn=packet_handler, timeout=duration, store=0)
        except Exception as e:
            pass
            
        return list(hosts.values())
    
    def _ping_sweep(self, network):
        """Perform ping sweep of network range"""
        hosts = []
        threads = []
        
        def ping_host(ip):
            try:
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', str(ip)], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    hosts.append({
                        'ip': str(ip),
                        'discovery_method': 'Ping Sweep',
                        'hostname': self._resolve_hostname(str(ip)),
                        'response_time': self._extract_ping_time(result.stdout)
                    })
            except:
                pass
        
        # Ping first 50 IPs to avoid being too aggressive
        for ip in list(network.hosts())[:50]:
            thread = threading.Thread(target=ping_host, args=(ip,))
            threads.append(thread)
            thread.start()
            
        # Wait for all threads
        for thread in threads:
            thread.join(timeout=2)
            
        return hosts
    
    def _syn_scan(self, network):
        """Perform TCP SYN scan on common ports"""
        hosts = []
        common_ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995]
        
        for ip in list(network.hosts())[:20]:  # Limit to first 20 IPs
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((str(ip), port))
                
                if result == 0:
                    open_ports.append(port)
                    
                sock.close()
                
            if open_ports:
                hosts.append({
                    'ip': str(ip),
                    'discovery_method': 'Port Scan',
                    'hostname': self._resolve_hostname(str(ip)),
                    'open_ports': open_ports
                })
                
        return hosts
    
    def _detect_services(self, ip):
        """Detect services running on discovered host"""
        services = {}
        common_ports = {
            22: 'SSH',
            23: 'Telnet', 
            53: 'DNS',
            80: 'HTTP',
            135: 'RPC',
            139: 'NetBIOS',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S'
        }
        
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                services[port] = {
                    'service': service,
                    'banner': self._grab_banner(ip, port)
                }
                
            sock.close()
            
        return services
    
    def _guess_os(self, host):
        """Guess operating system based on discovered information"""
        os_indicators = {
            'Windows': [135, 139, 445],
            'Linux': [22, 80, 443],
            'Router/IoT': [23, 80, 8080],
            'Apple': [548, 631]
        }
        
        open_ports = host.get('open_ports', [])
        services = host.get('services', {})
        
        scores = {}
        for os_name, indicator_ports in os_indicators.items():
            score = sum(1 for port in indicator_ports if port in open_ports)
            if score > 0:
                scores[os_name] = score
                
        # Check service banners for OS hints
        for port, service_info in services.items():
            banner = service_info.get('banner', '').lower()
            if 'windows' in banner or 'microsoft' in banner:
                scores['Windows'] = scores.get('Windows', 0) + 2
            elif 'linux' in banner or 'ubuntu' in banner:
                scores['Linux'] = scores.get('Linux', 0) + 2
                
        if scores:
            return max(scores, key=scores.get)
        return 'Unknown'
    
    def _resolve_hostname(self, ip):
        """Resolve hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return 'Unknown'
    
    def _grab_banner(self, ip, port):
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            if port == 80:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
            else:
                sock.send(b'\r\n')
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner.strip()
        except:
            return ''
    
    def _is_local_ip(self, ip):
        """Check if IP is in local network range"""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def _extract_ping_time(self, ping_output):
        """Extract ping response time from output"""
        try:
            match = re.search(r'time[<=](\d+)ms', ping_output)
            if match:
                return int(match.group(1))
        except:
            pass
        return None