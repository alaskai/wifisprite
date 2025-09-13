import socket
import requests
import time
import subprocess
import re
from scapy.all import *
import threading

class HoneypotDetector:
    def __init__(self):
        self.suspicious_indicators = []
        self.test_results = {}
        
    def detect_honeypot(self, network_info):
        """Comprehensive honeypot detection suite"""
        results = {
            'is_honeypot': False,
            'confidence': 0,
            'indicators': [],
            'tests_performed': []
        }
        
        # Test 1: Internet connectivity verification
        internet_test = self._test_internet_connectivity()
        results['tests_performed'].append('Internet Connectivity')
        if not internet_test['has_internet']:
            results['indicators'].append('No actual internet access detected')
            results['confidence'] += 30
            
        # Test 2: DNS response analysis
        dns_test = self._analyze_dns_responses()
        results['tests_performed'].append('DNS Analysis')
        if dns_test['suspicious']:
            results['indicators'].extend(dns_test['issues'])
            results['confidence'] += 25
            
        # Test 3: Gateway fingerprinting
        gateway_test = self._fingerprint_gateway()
        results['tests_performed'].append('Gateway Fingerprinting')
        if gateway_test['suspicious']:
            results['indicators'].extend(gateway_test['issues'])
            results['confidence'] += 20
            
        # Test 4: Captive portal analysis
        portal_test = self._analyze_captive_portal()
        results['tests_performed'].append('Captive Portal Analysis')
        if portal_test['suspicious']:
            results['indicators'].extend(portal_test['issues'])
            results['confidence'] += 15
            
        # Test 5: Network timing analysis
        timing_test = self._analyze_network_timing()
        results['tests_performed'].append('Network Timing')
        if timing_test['suspicious']:
            results['indicators'].extend(timing_test['issues'])
            results['confidence'] += 10
            
        # Determine if honeypot
        results['is_honeypot'] = results['confidence'] >= 50
        
        return results
    
    def _test_internet_connectivity(self):
        """Test actual internet connectivity vs fake responses"""
        test_sites = [
            'http://www.google.com',
            'http://www.microsoft.com', 
            'http://www.cloudflare.com',
            'http://httpbin.org/ip'
        ]
        
        results = {
            'has_internet': False,
            'response_times': [],
            'suspicious_responses': []
        }
        
        for site in test_sites:
            try:
                start_time = time.time()
                response = requests.get(site, timeout=5)
                response_time = time.time() - start_time
                
                results['response_times'].append(response_time)
                
                # Check for suspicious responses
                if response.status_code == 200:
                    # Check if response is too generic/fake
                    if len(response.text) < 100:
                        results['suspicious_responses'].append(f'{site}: Response too short')
                    elif 'captive' in response.text.lower():
                        results['suspicious_responses'].append(f'{site}: Captive portal detected')
                    else:
                        results['has_internet'] = True
                        
            except Exception as e:
                results['suspicious_responses'].append(f'{site}: {str(e)}')
                
        return results
    
    def _analyze_dns_responses(self):
        """Analyze DNS responses for spoofing indicators"""
        test_domains = [
            'google.com',
            'microsoft.com',
            'cloudflare.com',
            'nonexistentdomain12345.com'
        ]
        
        results = {
            'suspicious': False,
            'issues': []
        }
        
        responses = {}
        
        for domain in test_domains:
            try:
                ip = socket.gethostbyname(domain)
                responses[domain] = ip
                
                # Check for suspicious patterns
                if domain == 'nonexistentdomain12345.com':
                    results['suspicious'] = True
                    results['issues'].append('DNS returns IP for non-existent domain')
                    
            except socket.gaierror:
                # This is expected for non-existent domain
                if domain != 'nonexistentdomain12345.com':
                    results['issues'].append(f'DNS resolution failed for {domain}')
                    
        # Check if all domains resolve to same IP (DNS hijacking)
        unique_ips = set(responses.values())
        if len(unique_ips) == 1 and len(responses) > 1:
            results['suspicious'] = True
            results['issues'].append('All domains resolve to same IP (DNS hijacking)')
            
        return results
    
    def _fingerprint_gateway(self):
        """Fingerprint gateway/router for suspicious characteristics"""
        results = {
            'suspicious': False,
            'issues': [],
            'gateway_info': {}
        }
        
        try:
            # Get default gateway
            gateway_ip = self._get_default_gateway()
            if not gateway_ip:
                return results
                
            results['gateway_info']['ip'] = gateway_ip
            
            # Test HTTP response from gateway
            try:
                response = requests.get(f'http://{gateway_ip}', timeout=3)
                server_header = response.headers.get('Server', '')
                
                # Check for ESP32/Arduino indicators
                esp32_indicators = ['ESP32', 'Arduino', 'NodeMCU', 'Wemos']
                for indicator in esp32_indicators:
                    if indicator.lower() in server_header.lower():
                        results['suspicious'] = True
                        results['issues'].append(f'ESP32/Arduino device detected: {indicator}')
                        
                # Check for generic/suspicious server headers
                if not server_header or server_header in ['nginx', 'Apache']:
                    results['issues'].append('Generic or missing server header')
                    
            except:
                pass
                
            # Port scan for common ESP32 ports
            suspicious_ports = [80, 443, 8080, 8888, 4444]
            open_ports = []
            
            for port in suspicious_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((gateway_ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
                
            if len(open_ports) > 2:
                results['suspicious'] = True
                results['issues'].append(f'Multiple suspicious ports open: {open_ports}')
                
        except Exception as e:
            results['issues'].append(f'Gateway fingerprinting error: {str(e)}')
            
        return results
    
    def _analyze_captive_portal(self):
        """Analyze captive portal for suspicious characteristics"""
        results = {
            'suspicious': False,
            'issues': []
        }
        
        try:
            # Test for captive portal
            test_response = requests.get('http://detectportal.firefox.com/canonical.html', timeout=5)
            
            if test_response.status_code != 200 or 'success' not in test_response.text:
                # Captive portal detected, analyze it
                portal_response = requests.get('http://google.com', timeout=5)
                
                # Check for suspicious portal characteristics
                portal_content = portal_response.text.lower()
                
                suspicious_terms = [
                    'free wifi', 'click here', 'enter password',
                    'personal information', 'credit card', 'banking'
                ]
                
                for term in suspicious_terms:
                    if term in portal_content:
                        results['suspicious'] = True
                        results['issues'].append(f'Suspicious portal content: "{term}"')
                        
                # Check for HTTPS on portal
                if portal_response.url.startswith('http://'):
                    results['suspicious'] = True
                    results['issues'].append('Captive portal not using HTTPS')
                    
        except Exception as e:
            results['issues'].append(f'Captive portal analysis error: {str(e)}')
            
        return results
    
    def _analyze_network_timing(self):
        """Analyze network response timing for artificial patterns"""
        results = {
            'suspicious': False,
            'issues': []
        }
        
        try:
            # Test response times to multiple endpoints
            endpoints = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
            response_times = []
            
            for endpoint in endpoints:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((endpoint, 53))
                response_time = time.time() - start_time
                response_times.append(response_time)
                sock.close()
                
            # Check for artificially consistent timing (ESP32 characteristic)
            if len(set([round(t, 1) for t in response_times])) == 1:
                results['suspicious'] = True
                results['issues'].append('Artificially consistent response times detected')
                
            # Check for unusually fast responses (local fake responses)
            if all(t < 0.001 for t in response_times):
                results['suspicious'] = True
                results['issues'].append('Suspiciously fast responses (likely local/fake)')
                
        except Exception as e:
            results['issues'].append(f'Timing analysis error: {str(e)}')
            
        return results
    
    def _get_default_gateway(self):
        """Get the default gateway IP address"""
        try:
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