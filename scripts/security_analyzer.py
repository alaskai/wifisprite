import re
import socket
import ssl
import requests
from typing import Dict, List, Tuple
from urllib.parse import urlparse

class SecurityAnalyzer:
    def __init__(self):
        self.risk_factors = []
        self.recommendations = []
    
    def analyze_network_security(self, network_info: Dict) -> Dict:
        """Analyze network security and return risk assessment"""
        analysis = {
            'overall_risk': 'UNKNOWN',
            'risk_score': 0,
            'security_issues': [],
            'recommendations': [],
            'encryption_analysis': {},
            'network_analysis': {}
        }
        
        # Analyze encryption
        encryption_analysis = self._analyze_encryption(network_info)
        analysis['encryption_analysis'] = encryption_analysis
        analysis['risk_score'] += encryption_analysis['risk_points']
        
        # Analyze network characteristics
        network_analysis = self._analyze_network_characteristics(network_info)
        analysis['network_analysis'] = network_analysis
        analysis['risk_score'] += network_analysis['risk_points']
        
        # Determine overall risk level
        analysis['overall_risk'] = self._calculate_risk_level(analysis['risk_score'])
        
        # Compile security issues and recommendations
        analysis['security_issues'] = self._compile_security_issues(encryption_analysis, network_analysis)
        analysis['recommendations'] = self._generate_recommendations(analysis['overall_risk'], analysis['security_issues'])
        
        return analysis
    
    def _analyze_encryption(self, network_info: Dict) -> Dict:
        """Analyze encryption strength and type"""
        encryption = network_info.get('encryption', '').upper()
        authentication = network_info.get('authentication', '').upper()
        
        analysis = {
            'type': encryption if encryption != 'UNKNOWN' else 'Unknown',
            'strength': 'UNKNOWN',
            'risk_points': 0,
            'issues': [],
            'description': ''
        }
        
        # Handle unknown encryption by checking authentication
        if encryption == 'UNKNOWN' or not encryption:
            if 'WPA3' in authentication:
                encryption = 'WPA3'
                analysis['type'] = 'WPA3'
            elif 'WPA2' in authentication:
                encryption = 'WPA2'
                analysis['type'] = 'WPA2'
            elif 'WPA' in authentication:
                encryption = 'WPA'
                analysis['type'] = 'WPA'
            elif 'WEP' in authentication:
                encryption = 'WEP'
                analysis['type'] = 'WEP'
            elif 'OPEN' in authentication or 'NONE' in authentication:
                encryption = 'NONE'
                analysis['type'] = 'None'
        
        # Analyze encryption strength
        if not encryption or encryption == 'NONE' or encryption == 'UNKNOWN' or 'OPEN' in authentication:
            if encryption == 'UNKNOWN':
                analysis['strength'] = 'UNKNOWN'
                analysis['risk_points'] = 40
                analysis['issues'].append('Unable to determine encryption type - proceed with caution')
                analysis['description'] = 'Encryption type could not be determined'
            else:
                analysis['strength'] = 'NONE'
                analysis['risk_points'] = 100
                analysis['issues'].append('No encryption - all data transmitted in plain text')
                analysis['description'] = 'Open network with no security'
            
        elif 'WEP' in encryption:
            analysis['strength'] = 'VERY_WEAK'
            analysis['risk_points'] = 80
            analysis['issues'].append('WEP encryption is easily breakable')
            analysis['description'] = 'Outdated WEP encryption (easily cracked)'
            
        elif 'WPA3' in encryption:
            analysis['strength'] = 'STRONG'
            analysis['risk_points'] = 10
            analysis['description'] = 'Modern WPA3 encryption (recommended)'
            
        elif 'WPA2' in encryption:
            analysis['strength'] = 'GOOD'
            analysis['risk_points'] = 20
            analysis['description'] = 'WPA2 encryption (acceptable but aging)'
            
        elif 'WPA' in encryption:
            analysis['strength'] = 'WEAK'
            analysis['risk_points'] = 60
            analysis['issues'].append('WPA encryption has known vulnerabilities')
            analysis['description'] = 'Outdated WPA encryption'
            
        return analysis
    
    def _analyze_network_characteristics(self, network_info: Dict) -> Dict:
        """Analyze network naming and characteristics for suspicious patterns"""
        ssid = network_info.get('ssid', '')
        signal_strength = network_info.get('signal_strength', 0)
        
        analysis = {
            'suspicious_naming': False,
            'signal_analysis': {},
            'risk_points': 0,
            'issues': []
        }
        
        # Check for suspicious SSID patterns
        suspicious_patterns = [
            r'free.*wifi',
            r'public.*wifi',
            r'guest.*network',
            r'.*hotspot.*',
            r'linksys',
            r'netgear',
            r'dlink',
            r'default.*',
            r'.*_nomap'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, ssid.lower()):
                analysis['suspicious_naming'] = True
                analysis['risk_points'] += 15
                analysis['issues'].append(f'Suspicious network name pattern: {ssid}')
                break
        
        # Analyze signal strength
        if signal_strength > 80:
            analysis['signal_analysis'] = {
                'strength': 'Very Strong',
                'risk': 'Could indicate close proximity or powerful transmitter'
            }
            analysis['risk_points'] += 5
        elif signal_strength < 30:
            analysis['signal_analysis'] = {
                'strength': 'Weak',
                'risk': 'Weak signal may indicate connection issues'
            }
            analysis['risk_points'] += 10
        
        return analysis
    
    def _calculate_risk_level(self, risk_score: int) -> str:
        """Calculate overall risk level based on score"""
        if risk_score >= 80:
            return 'HIGH'
        elif risk_score >= 50:
            return 'MEDIUM'
        elif risk_score >= 30:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _compile_security_issues(self, encryption_analysis: Dict, network_analysis: Dict) -> List[str]:
        """Compile all identified security issues"""
        issues = []
        issues.extend(encryption_analysis.get('issues', []))
        issues.extend(network_analysis.get('issues', []))
        return issues
    
    def _generate_recommendations(self, risk_level: str, issues: List[str]) -> List[str]:
        """Generate security recommendations based on risk level"""
        recommendations = []
        
        if risk_level == 'HIGH':
            recommendations.extend([
                'DO NOT use this network for sensitive activities',
                'Use a VPN if you must connect',
                'Avoid accessing banking, email, or personal accounts',
                'Consider using mobile data instead'
            ])
        elif risk_level == 'MEDIUM':
            recommendations.extend([
                'Use with caution - enable VPN before connecting',
                'Avoid sensitive transactions without VPN',
                'Verify network legitimacy with venue staff',
                'Monitor for suspicious activity'
            ])
        elif risk_level == 'LOW':
            recommendations.extend([
                'Generally safe but use VPN for sensitive data',
                'Verify this is the official network',
                'Keep software updated',
                'Use HTTPS websites only'
            ])
        else:
            recommendations.extend([
                'Network appears secure',
                'Still recommended to use VPN for privacy',
                'Verify network authenticity',
                'Follow general security practices'
            ])
        
        return recommendations
    
    def check_captive_portal(self) -> Dict:
        """Check for captive portal (indicates public network)"""
        try:
            response = requests.get('http://detectportal.firefox.com/canonical.html', 
                                  timeout=5, allow_redirects=False)
            
            if response.status_code == 200 and 'success' in response.text.lower():
                return {'has_captive_portal': False, 'direct_internet': True}
            else:
                return {'has_captive_portal': True, 'direct_internet': False}
                
        except requests.RequestException:
            return {'has_captive_portal': 'Unknown', 'direct_internet': 'Unknown'}