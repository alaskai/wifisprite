import socket
import requests
import time
import subprocess
import json

class DNSAnalyzer:
    def __init__(self):
        self.test_domains = [
            'google.com',
            'facebook.com', 
            'github.com',
            'microsoft.com',
            'cloudflare.com'
        ]
        
    def analyze_dns_security(self):
        """Comprehensive DNS security analysis"""
        results = {
            'dns_hijacking': [],
            'dns_filtering': [],
            'dns_performance': {},
            'security_issues': [],
            'recommendations': []
        }
        
        # Test for DNS hijacking
        hijacking_results = self._test_dns_hijacking()
        results['dns_hijacking'] = hijacking_results
        
        # Test for DNS filtering/blocking
        filtering_results = self._test_dns_filtering()
        results['dns_filtering'] = filtering_results
        
        # Test DNS performance and reliability
        performance_results = self._test_dns_performance()
        results['dns_performance'] = performance_results
        
        # Test for DNS over HTTPS support
        doh_results = self._test_dns_over_https()
        results['doh_support'] = doh_results
        
        # Check for DNS leaks
        leak_results = self._test_dns_leaks()
        results['dns_leaks'] = leak_results
        
        # Generate security recommendations
        results['recommendations'] = self._generate_dns_recommendations(results)
        
        return results
    
    def _test_dns_hijacking(self):
        """Test for DNS hijacking and redirection"""
        hijacking_indicators = []
        
        # Test resolution of known domains
        for domain in self.test_domains:
            try:
                # Get IP from system DNS
                system_ip = socket.gethostbyname(domain)
                
                # Compare with known good DNS (Cloudflare)
                cloudflare_ip = self._resolve_with_dns(domain, '1.1.1.1')
                google_ip = self._resolve_with_dns(domain, '8.8.8.8')
                
                # Check for discrepancies
                if system_ip != cloudflare_ip and system_ip != google_ip:
                    hijacking_indicators.append({
                        'domain': domain,
                        'system_ip': system_ip,
                        'cloudflare_ip': cloudflare_ip,
                        'google_ip': google_ip,
                        'issue': 'DNS resolution mismatch - possible hijacking'
                    })
                    
            except Exception as e:
                hijacking_indicators.append({
                    'domain': domain,
                    'error': str(e),
                    'issue': 'DNS resolution failed'
                })
                
        # Test non-existent domain resolution
        fake_domain = 'nonexistentdomain12345.com'
        try:
            fake_ip = socket.gethostbyname(fake_domain)
            hijacking_indicators.append({
                'domain': fake_domain,
                'resolved_ip': fake_ip,
                'issue': 'Non-existent domain resolves to IP - DNS hijacking detected'
            })
        except socket.gaierror:
            pass  # Expected behavior
            
        return hijacking_indicators
    
    def _test_dns_filtering(self):
        """Test for DNS filtering and content blocking"""
        filtering_results = []
        
        # Test domains that might be filtered
        test_categories = {
            'social_media': ['facebook.com', 'twitter.com', 'instagram.com'],
            'streaming': ['youtube.com', 'netflix.com', 'twitch.tv'],
            'news': ['bbc.com', 'cnn.com', 'reuters.com'],
            'tech': ['github.com', 'stackoverflow.com', 'reddit.com']
        }
        
        for category, domains in test_categories.items():
            blocked_domains = []
            
            for domain in domains:
                try:
                    # Try to resolve domain
                    ip = socket.gethostbyname(domain)
                    
                    # Check if resolved to common blocking IPs
                    blocking_ips = [
                        '0.0.0.0',
                        '127.0.0.1', 
                        '10.0.0.1',
                        '192.168.1.1'
                    ]
                    
                    if ip in blocking_ips:
                        blocked_domains.append(domain)
                        
                except socket.gaierror:
                    blocked_domains.append(domain)
                    
            if blocked_domains:
                filtering_results.append({
                    'category': category,
                    'blocked_domains': blocked_domains,
                    'issue': f'{category.replace("_", " ").title()} sites appear to be blocked'
                })
                
        return filtering_results
    
    def _test_dns_performance(self):
        """Test DNS performance and reliability"""
        performance = {
            'response_times': {},
            'reliability': {},
            'issues': []
        }
        
        # Test different DNS servers
        dns_servers = {
            'System Default': None,
            'Cloudflare': '1.1.1.1',
            'Google': '8.8.8.8',
            'OpenDNS': '208.67.222.222'
        }
        
        for dns_name, dns_ip in dns_servers.items():
            response_times = []
            successful_queries = 0
            
            for domain in self.test_domains[:3]:  # Test first 3 domains
                try:
                    start_time = time.time()
                    
                    if dns_ip:
                        result = self._resolve_with_dns(domain, dns_ip)
                    else:
                        result = socket.gethostbyname(domain)
                        
                    response_time = (time.time() - start_time) * 1000  # Convert to ms
                    response_times.append(response_time)
                    successful_queries += 1
                    
                except Exception:
                    response_times.append(None)
                    
            # Calculate statistics
            valid_times = [t for t in response_times if t is not None]
            if valid_times:
                avg_time = sum(valid_times) / len(valid_times)
                performance['response_times'][dns_name] = {
                    'average_ms': round(avg_time, 2),
                    'min_ms': round(min(valid_times), 2),
                    'max_ms': round(max(valid_times), 2)
                }
            else:
                performance['response_times'][dns_name] = {'error': 'All queries failed'}
                
            performance['reliability'][dns_name] = {
                'success_rate': f'{(successful_queries/len(self.test_domains[:3]))*100:.1f}%',
                'successful_queries': successful_queries
            }
            
        # Identify performance issues
        system_avg = performance['response_times'].get('System Default', {}).get('average_ms', 0)
        if system_avg > 500:  # More than 500ms
            performance['issues'].append('Slow DNS response times detected')
            
        return performance
    
    def _test_dns_over_https(self):
        """Test DNS over HTTPS (DoH) support and functionality"""
        doh_results = {
            'supported': False,
            'providers_tested': {},
            'issues': []
        }
        
        # Test popular DoH providers
        doh_providers = {
            'Cloudflare': 'https://1.1.1.1/dns-query',
            'Google': 'https://dns.google/dns-query',
            'Quad9': 'https://dns.quad9.net/dns-query'
        }
        
        for provider, url in doh_providers.items():
            try:
                # Test DoH query
                headers = {'Accept': 'application/dns-json'}
                params = {'name': 'google.com', 'type': 'A'}
                
                response = requests.get(url, headers=headers, params=params, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    if 'Answer' in data:
                        doh_results['supported'] = True
                        doh_results['providers_tested'][provider] = 'Working'
                    else:
                        doh_results['providers_tested'][provider] = 'No answer received'
                else:
                    doh_results['providers_tested'][provider] = f'HTTP {response.status_code}'
                    
            except Exception as e:
                doh_results['providers_tested'][provider] = f'Error: {str(e)}'
                
        if not doh_results['supported']:
            doh_results['issues'].append('DNS over HTTPS not accessible - possible blocking')
            
        return doh_results
    
    def _test_dns_leaks(self):
        """Test for DNS leaks that might expose browsing activity"""
        leak_results = {
            'potential_leaks': [],
            'dns_servers_detected': [],
            'issues': []
        }
        
        try:
            # Get current DNS servers from system
            dns_servers = self._get_system_dns_servers()
            leak_results['dns_servers_detected'] = dns_servers
            
            # Check if DNS servers are from ISP or public
            for dns_server in dns_servers:
                if self._is_isp_dns(dns_server):
                    leak_results['potential_leaks'].append({
                        'dns_server': dns_server,
                        'issue': 'Using ISP DNS - browsing activity may be logged'
                    })
                    
        except Exception as e:
            leak_results['issues'].append(f'DNS leak test failed: {str(e)}')
            
        return leak_results
    
    def _resolve_with_dns(self, domain, dns_server):
        """Resolve domain using specific DNS server"""
        try:
            # Use nslookup command for Windows
            result = subprocess.run(
                ['nslookup', domain, dns_server],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Parse nslookup output
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Address:' in line and dns_server not in line:
                    ip = line.split('Address:')[-1].strip()
                    if self._is_valid_ip(ip):
                        return ip
                        
        except Exception:
            pass
            
        return None
    
    def _get_system_dns_servers(self):
        """Get DNS servers configured on the system"""
        dns_servers = []
        
        try:
            # Use ipconfig /all to get DNS servers
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'DNS Servers' in line:
                    # Extract IP address
                    parts = line.split(':')
                    if len(parts) > 1:
                        ip = parts[1].strip()
                        if self._is_valid_ip(ip):
                            dns_servers.append(ip)
                            
        except Exception:
            pass
            
        return dns_servers
    
    def _is_isp_dns(self, dns_server):
        """Check if DNS server likely belongs to ISP"""
        # Common public DNS servers
        public_dns = [
            '1.1.1.1', '1.0.0.1',  # Cloudflare
            '8.8.8.8', '8.8.4.4',  # Google
            '208.67.222.222', '208.67.220.220',  # OpenDNS
            '9.9.9.9', '149.112.112.112'  # Quad9
        ]
        
        return dns_server not in public_dns
    
    def _is_valid_ip(self, ip_string):
        """Check if string is a valid IP address"""
        try:
            socket.inet_aton(ip_string)
            return True
        except socket.error:
            return False
    
    def _generate_dns_recommendations(self, results):
        """Generate DNS security recommendations"""
        recommendations = []
        
        # Check for hijacking
        if results['dns_hijacking']:
            recommendations.append('🚨 DNS hijacking detected - network is compromised')
            recommendations.append('🔴 Disconnect from this network immediately')
            recommendations.append('🛡️ Use secure DNS servers (1.1.1.1 or 8.8.8.8)')
            
        # Check for filtering
        if results['dns_filtering']:
            recommendations.append('⚠️ DNS filtering detected - content may be blocked')
            recommendations.append('🔒 Consider using VPN for unrestricted access')
            
        # Check performance
        performance = results.get('dns_performance', {})
        if performance.get('issues'):
            recommendations.append('⏱️ Slow DNS performance detected')
            recommendations.append('💡 Consider switching to faster DNS servers')
            
        # Check DoH support
        doh = results.get('doh_support', {})
        if not doh.get('supported'):
            recommendations.append('🔒 DNS over HTTPS blocked - privacy may be compromised')
            recommendations.append('🛡️ Use VPN to encrypt DNS queries')
            
        # Check for leaks
        leaks = results.get('dns_leaks', {})
        if leaks.get('potential_leaks'):
            recommendations.append('📡 DNS leaks detected - browsing activity may be monitored')
            recommendations.append('🔐 Configure secure DNS servers manually')
            
        # General recommendations
        recommendations.extend([
            '💡 Use DNS over HTTPS when possible',
            '💡 Regularly check DNS settings',
            '💡 Consider using privacy-focused DNS providers'
        ])
        
        return recommendations