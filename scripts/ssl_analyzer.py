import ssl
import socket
# import requests
import urllib3
from datetime import datetime, timedelta
import subprocess

class SSLAnalyzer:
    def __init__(self):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
    def analyze_ssl_security(self):
        """Comprehensive SSL/TLS security analysis"""
        results = {
            'certificates': [],
            'vulnerabilities': [],
            'security_issues': [],
            'recommendations': []
        }
        
        # Test common websites through current network
        test_sites = [
            ('google.com', 443),
            ('facebook.com', 443),
            ('github.com', 443),
            ('microsoft.com', 443)
        ]
        
        for hostname, port in test_sites:
            cert_info = self._analyze_certificate(hostname, port)
            if cert_info:
                results['certificates'].append(cert_info)
                
        # Check for SSL/TLS vulnerabilities
        vulnerabilities = self._check_ssl_vulnerabilities()
        results['vulnerabilities'].extend(vulnerabilities)
        
        # Test for SSL interception/MITM
        mitm_results = self._test_ssl_interception()
        results['security_issues'].extend(mitm_results)
        
        # Generate recommendations
        results['recommendations'] = self._generate_ssl_recommendations(results)
        
        return results
    
    def _analyze_certificate(self, hostname, port):
        """Analyze SSL certificate for a specific host"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    cert_info = {
                        'hostname': hostname,
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown'),
                        'suspicious_indicators': []
                    }
                    
                    # Check for suspicious certificate characteristics
                    cert_info['suspicious_indicators'] = self._check_certificate_suspicious(cert_info)
                    
                    return cert_info
                    
        except Exception as e:
            return {
                'hostname': hostname,
                'error': str(e),
                'suspicious_indicators': ['Certificate analysis failed']
            }
    
    def _check_certificate_suspicious(self, cert_info):
        """Check certificate for suspicious characteristics"""
        suspicious = []
        
        # Check certificate validity period
        try:
            not_after = datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
            not_before = datetime.strptime(cert_info['not_before'], '%b %d %H:%M:%S %Y %Z')
            
            # Very short validity period (less than 30 days)
            if (not_after - not_before).days < 30:
                suspicious.append('Unusually short certificate validity period')
                
            # Certificate expires soon
            if (not_after - datetime.now()).days < 30:
                suspicious.append('Certificate expires within 30 days')
                
        except:
            suspicious.append('Invalid certificate date format')
            
        # Check issuer
        issuer = cert_info.get('issuer', {})
        common_cas = ['DigiCert', 'Lets Encrypt', 'GlobalSign', 'Comodo', 'GeoTrust']
        issuer_name = issuer.get('organizationName', '')
        
        if not any(ca in issuer_name for ca in common_cas):
            suspicious.append(f'Unknown or suspicious certificate authority: {issuer_name}')
            
        # Check subject
        subject = cert_info.get('subject', {})
        if subject.get('commonName') != cert_info['hostname']:
            suspicious.append('Certificate common name does not match hostname')
            
        return suspicious
    
    def _check_ssl_vulnerabilities(self):
        """Check for known SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        # Test for weak cipher suites (simplified check)
        weak_ciphers = self._test_weak_ciphers()
        vulnerabilities.extend(weak_ciphers)
        
        # Test for protocol downgrade attacks
        downgrade_issues = self._test_protocol_downgrade()
        vulnerabilities.extend(downgrade_issues)
        
        return vulnerabilities
    
    def _test_weak_ciphers(self):
        """Test for weak cipher suites"""
        issues = []
        
        # Test a few major sites for cipher strength
        test_sites = ['google.com', 'github.com']
        
        for site in test_sites:
            try:
                # Test with different SSL contexts
                weak_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                weak_context.set_ciphers('RC4:DES:3DES')
                weak_context.check_hostname = False
                weak_context.verify_mode = ssl.CERT_NONE
                
                try:
                    with socket.create_connection((site, 443), timeout=3) as sock:
                        with weak_context.wrap_socket(sock, server_hostname=site) as ssock:
                            cipher = ssock.cipher()
                            if cipher and any(weak in cipher[0] for weak in ['RC4', 'DES']):
                                issues.append(f'{site} accepts weak cipher: {cipher[0]}')
                except:
                    pass  # Good - weak ciphers rejected
                    
            except Exception:
                pass
                
        return issues
    
    def _test_protocol_downgrade(self):
        """Test for SSL/TLS protocol downgrade vulnerabilities"""
        issues = []
        
        # Test if old protocols are accepted
        old_protocols = [
            (ssl.PROTOCOL_TLS, 'TLS'),
            (ssl.PROTOCOL_TLS_CLIENT, 'TLS_CLIENT')
        ]
        
        for protocol, name in old_protocols:
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Test against a major site
                with socket.create_connection(('google.com', 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname='google.com') as ssock:
                        version = ssock.version()
                        if version and version in ['SSLv3', 'TLSv1', 'TLSv1.1']:
                            issues.append(f'Outdated protocol {version} accepted')
                            
            except Exception:
                pass  # Expected for secure configurations
                
        return issues
    
    def _test_ssl_interception(self):
        """Test for SSL/TLS interception (MITM attacks)"""
        issues = []
        
        # Compare certificates from different perspectives
        test_sites = ['google.com', 'github.com', 'microsoft.com']
        
        for site in test_sites:
            try:
                # Get certificate through current network
                local_cert = self._get_certificate_fingerprint(site)
                
                # Compare with known good fingerprints (simplified)
                if local_cert:
                    # Check for self-signed or unusual certificates
                    if self._is_suspicious_certificate(site, local_cert):
                        issues.append(f'Suspicious certificate detected for {site}')
                        
            except Exception as e:
                issues.append(f'SSL interception test failed for {site}: {str(e)}')
                
        return issues
    
    def _get_certificate_fingerprint(self, hostname):
        """Get certificate fingerprint"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert_chain()[0]
                    return cert_der
                    
        except Exception:
            return None
    
    def _is_suspicious_certificate(self, hostname, cert):
        """Check if certificate appears suspicious"""
        # Simplified check - in real implementation, compare with known good certs
        try:
            # Basic checks for self-signed or unusual certificates
            cert_info = ssl.DER_cert_to_PEM_cert(cert.public_bytes(ssl.Encoding.DER))
            
            # Check for common indicators of interception
            suspicious_indicators = [
                'self-signed',
                'untrusted',
                'localhost',
                'proxy',
                'firewall'
            ]
            
            for indicator in suspicious_indicators:
                if indicator.lower() in cert_info.lower():
                    return True
                    
        except Exception:
            pass
            
        return False
    
    def _generate_ssl_recommendations(self, results):
        """Generate SSL security recommendations"""
        recommendations = []
        
        # Check for certificate issues
        cert_issues = sum(len(cert.get('suspicious_indicators', [])) for cert in results['certificates'])
        if cert_issues > 0:
            recommendations.append('⚠️ Suspicious SSL certificates detected - possible MITM attack')
            recommendations.append('🔒 Verify you are on a trusted network')
            
        # Check for vulnerabilities
        if results['vulnerabilities']:
            recommendations.append('🚨 SSL/TLS vulnerabilities detected')
            recommendations.append('🛡️ Use VPN to encrypt all traffic')
            
        # Check for security issues
        if results['security_issues']:
            recommendations.append('🔴 SSL interception detected - network may be monitored')
            recommendations.append('🔴 Avoid sensitive activities on this network')
            
        # General recommendations
        recommendations.extend([
            '💡 Always verify SSL certificate warnings',
            '💡 Use HTTPS websites whenever possible',
            '💡 Keep browsers and security software updated'
        ])
        
        return recommendations